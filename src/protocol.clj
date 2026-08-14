(ns protocol
  "Protocol-agnostic tshark log pipeline. Each wire protocol (dynamodb,
   the memcache logic still in process, ...) plugs in by adding
   defmethods to the multimethods here from its own namespace -- nothing in
   this file mentions a protocol by name."
  (:require [charred.api :as charred]
            [clojure.java.io :as io]))

; Utils
(defn some-vals [m]
  (into (empty m) (remove (comp nil? val)) m))
(defn ->vec [x]
  (cond (nil? x) [] (sequential? x) (vec x) :else [x]))
(defn ->long [x] (when x (parse-long (str x))))

(defn hex->bytes ^bytes [^String hex]
  (if (empty? hex)
    (byte-array 0)
    (let [n (quot (inc (.length hex)) 3)]
      (->> (range n)
           (mapv #(let [pos (* % 3)] (unchecked-byte (Integer/parseInt hex pos (+ pos 2) 16))))
           (byte-array)))))
(defn update-in-if-present [m ks f]
  (if (not= ::missing (get-in m ks ::missing))
    (update-in m ks f)
    m))
(defn- decode-byte-strings [record]
  (-> record
      (update-in-if-present [:layers :tcp :tcp_tcp_payload] hex->bytes)
      (update-in-if-present [:layers :http :http_http_file_data] hex->bytes)
      (update-in-if-present [:layers :tcp_tcp_reassembled_data] hex->bytes)))
(defn- reliable-payload [layers]
  (or (:tcp_tcp_reassembled_data layers)
      (get-in layers [:tcp :tcp_tcp_payload])))
(defn- add-payload [record]
  (assoc-in record [:layers :tcp :tcp_payload] (reliable-payload (:layers record))))

(defmulti protocol-matches?
  "Does `record` belong to `proto`, given that `proto` already owns one of
   record's ports (per the caller-supplied ports map)? Dispatches on proto
   itself, so each protocol only has to confirm that tshark actually
   dissected its layer out of this record (e.g. :http present for
   :dynamodb) -- not re-check the port, which match-protocol already used
   to narrow the candidates."
  (fn [proto _record] proto))

(defn- record-ports
  "The record's own port(s), as ints -- tshark's tcp.port is a pseudo-field
   matching either direction, so this is usually a 1- or 2-element set."
  [record]
  (into #{} (keep ->long) (->vec (get-in record [:layers :tcp :tcp_tcp_port]))))

(defn validate-ports!
  "Throws if `ports` (a {port -> protocol-keyword} map) names a protocol
   keyword nothing registered a protocol-matches? method for. Called once,
   up front, so a typo in the ports map fails with one clear message
   instead of a bare multimethod dispatch exception on the first matching
   record deep in the log."
  [ports]
  (let [known   (set (keys (methods protocol-matches?)))
        unknown (remove known (vals ports))]
    (when (seq unknown)
      (throw (ex-info (str "Unknown protocol(s) in ports map: " (vec unknown)
                            " -- registered protocols are " known)
                       {:unknown unknown :known known})))))

(defn match-protocol
  "Looks up record's own port(s) in `ports` ({port -> protocol-keyword}) to
   get the protocol(s) that own one of them, then confirms with
   protocol-matches?. Throws if more than one protocol matches -- ambiguous
   port ownership is a configuration bug to surface loudly, not something
   to silently break a tie on by hash-map iteration order."
  [ports record]
  (let [candidates (into #{} (keep ports) (record-ports record))
        matches    (filterv #(protocol-matches? % record) candidates)]
    (case (count matches)
      0 nil
      1 (first matches)
      (throw (ex-info (str "Ambiguous protocol match -- record matches more than one protocol: " matches)
                       {:candidates matches :record record})))))

(defmulti split-protocol-messages :protocol)
(defmethod split-protocol-messages :default [m] [m])

(defmulti extract-and-decode-fields :protocol)

(defn tshark-log-xform
  "Transducer parsing raw tshark log lines into decoded event maps. `ports`
   ({port -> protocol-keyword}, e.g. {8000 :dynamodb, 11211 :memcache}) is
   the sole source of protocol identity by port -- see match-protocol.
   `since` (epoch millis, or nil for no cutoff) drops records earlier than
   it before any of the heavier protocol-matching/byte-decoding steps run,
   so a log spanning several sessions doesn't pay to process the ones
   read-messages' caller doesn't want."
  [ports since]
  (comp
    (map #(charred/read-json % :key-fn keyword))
    (remove :index)                                  ; drop EK bulk-index lines
    (filter #(or (nil? since) (>= (->long (:timestamp %)) since)))
    (remove (comp #{"0"} :tcp_tcp_len :tcp :layers))  ; drop Syn/Ack/Fin
    (map #(assoc % :protocol (match-protocol ports %)))
    (filter :protocol)
    (map decode-byte-strings)
    (map add-payload)
    (mapcat split-protocol-messages)
    (map extract-and-decode-fields)))

(defn read-messages
  "`ports` ({port -> protocol-keyword}) is required and comes first -- it is
   the sole source of protocol identity by port, and its values are
   validated eagerly against the registered protocols (see validate-ports!)
   before any of the log is read. `since` (epoch millis) is optional; nil
   (or omitted) means no cutoff."
  ([ports tshark-log-file] (read-messages ports tshark-log-file nil))
  ([ports tshark-log-file since]
   (validate-ports! ports)
   (with-open [rdr (io/reader tshark-log-file)]
     (into [] (tshark-log-xform ports since) (line-seq rdr)))))

(defmulti noise?
          "Is `event` (a request) traffic worth dropping from the diagram?
           Dispatches on :protocol so each protocol can register its own
           noise, e.g. the transactor's pod-coord heartbeat for :dynamodb.
           Assumes only requests are asked -- remove-noise only ever calls
           this on events for which `request?` is true, so a method never
           needs to handle a response shape."
          :protocol)
(defmethod noise? :default [_] false)

(defmulti request?
          "Is `event` a request (as opposed to a response)? Dispatches on :protocol
           so remove-noise's request/response pairing stays protocol-agnostic.
           Assumes request/response for that protocol can be told apart from
           the event map alone (no external state), and that responses carry
           no such marker of their own -- remove-noise relies on `noise?`
           only ever being asked about requests, and on responses being
           matched up by stream order instead."
          :protocol)
(defmethod request? :default [_] false)

(defmulti correlation-id
  "Per-stream token pairing a request with its response, used by
   remove-noise. Dispatches on :protocol. :default returns nil, meaning
   \"no real wire-level token -- tag-correlation-ids should fall back to a
   per-stream auto-incrementing counter instead\", which matches the old
   FIFO-queue assumption exactly (responses come back in the order their
   requests were sent). A protocol with a real correlation token (e.g.
   memcache's opaque field) overrides this to return it directly, so
   out-of-order responses or multiplexed exchanges on one stream still pair
   correctly -- see tag-correlation-ids."
  :protocol)
(defmethod correlation-id :default [_] nil)

(defn- tag-correlation-ids
  "Assigns :correlation-id to every event. When correlation-id returns
   non-nil for an event, that's used directly (both the request and its
   response resolve to the same real token, independent of ordering). When
   it returns nil (the :default case), falls back to a per-stream counter:
   the Nth request on a stream gets counter N, and the next non-request
   event on that stream that hasn't already resolved to an explicit token
   is assumed to be its response and gets N too -- the FIFO order
   assumption remove-noise previously implemented directly, now expressed
   as id generation instead of a verdict queue."
  [events]
  (loop [[e & more] events, counters {}, pending {}, acc (transient [])]
    (if-not e
      (persistent! acc)
      (let [stream   (:stream e)
            explicit (correlation-id e)]
        (cond
          (some? explicit)
          (recur more counters pending (conj! acc (assoc e :correlation-id explicit)))

          (request? e)
          (let [n (inc (get counters stream 0))]
            (recur more (assoc counters stream n)
                   (update pending stream (fnil conj []) n)
                   (conj! acc (assoc e :correlation-id n))))

          (seq (get pending stream))
          (let [id (first (get pending stream))]
            (recur more counters (update pending stream (comp vec rest))
                   (conj! acc (assoc e :correlation-id id))))

          :else
          (recur more counters pending (conj! acc (assoc e :correlation-id nil))))))))

(defn remove-noise
  "Drops noisy request/response pairs, paired up by (:stream
   :correlation-id) -- see tag-correlation-ids for how that id is
   assigned. For each request, noise? decides whether to drop it; every
   other event sharing its (stream, id) is dropped alongside it. An event
   whose (stream, id) never matches a request's (e.g. a protocol that never
   registers request?, or an orphan response) just passes through
   untouched."
  [events]
  (let [tagged   (tag-correlation-ids events)
        dropped? (into #{}
                        (comp (filter request?) (filter noise?) (map (juxt :stream :correlation-id)))
                        tagged)]
    (into [] (remove (comp dropped? (juxt :stream :correlation-id))) tagged)))

(comment
  ;; require the protocols you want registered -- read-messages only knows
  ;; about protocols whose namespace has been loaded (their defmethods run
  ;; as a side effect of loading), same as process/draw-diagram!'s own
  ;; `(require '[dynamodb] '[memcache])`.
  (require '[dynamodb] '[memcache] '[http])

  (def ports {8000 :dynamodb, 11211 :memcache})

  ;; The decoded event maps draw-diagram! would otherwise turn straight into
  ;; an SVG -- handy at the REPL to inspect/filter/tally without generating
  ;; a diagram at all.
  (def events (read-messages (assoc ports 8000 :http) "/tmp/tshark.log"))
  (count events)
  (frequencies (map :protocol events))
  (first (filter #(= :dynamodb (:protocol %)) events))

  ;; `since` (e.g. setup's start-all!/region timestamps) drops earlier
  ;; records before any protocol-matching/decoding runs.
  (read-messages ports "/tmp/tshark.log" (- (System/currentTimeMillis) 60000))

  ;; remove-noise is the same request/response-pairing pass draw-diagram!
  ;; applies by default (its :remove-noise? true).
  (count (remove-noise events))

  ;; Point a port straight at :http (see http.clj's ns docstring) to inspect
  ;; raw decoded HTTP instead of a protocol built on top of it.
  (read-messages {8000 :http} "/tmp/tshark.log"))
