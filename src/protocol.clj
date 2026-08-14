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
  "Does `record` belong to `proto`? Dispatches on proto itself, so each
   protocol owns its own matching rule instead of going through one shared
   port+layer check."
  (fn [proto _record] proto))

(defn match-protocol
  "First registered protocol (via protocol-matches?) that record matches."
  [record]
  (some #(when (protocol-matches? % record) %) (keys (methods protocol-matches?))))

(defmulti split-protocol-messages :protocol)
(defmethod split-protocol-messages :default [m] [m])

(defmulti extract-and-decode-fields :protocol)

(defn tshark-log-xform
  "Transducer parsing raw tshark log lines into decoded event maps. `since`
   (epoch millis, or nil for no cutoff) drops records earlier than it before
   any of the heavier protocol-matching/byte-decoding steps run, so a log
   spanning several sessions doesn't pay to process the ones read-messages'
   caller doesn't want."
  [since]
  (comp
    (map #(charred/read-json % :key-fn keyword))
    (remove :index)                                  ; drop EK bulk-index lines
    (filter #(or (nil? since) (>= (->long (:timestamp %)) since)))
    (remove (comp #{"0"} :tcp_tcp_len :tcp :layers))  ; drop Syn/Ack/Fin
    (map #(assoc % :protocol (match-protocol %)))
    (filter :protocol)
    (map decode-byte-strings)
    (map add-payload)
    (mapcat split-protocol-messages)
    (map extract-and-decode-fields)))

(defn read-messages
  ([tshark-log-file] (read-messages tshark-log-file nil))
  ([tshark-log-file since]
   (with-open [rdr (io/reader tshark-log-file)]
     (into [] (tshark-log-xform since) (line-seq rdr)))))

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

(defn remove-noise
  "Drops noisy request/response pairs. For each event, request? decides
   whether it's a request; if so, noise? decides whether to drop it, and
   that verdict is pushed onto a per-stream FIFO queue in `pending` (so a
   stream with several in-flight requests remembers each one's verdict in
   order). A non-request event on a stream with a pending queue is treated
   as that request's response: it pops the oldest verdict off the queue and
   is dropped iff its paired request was. This assumes responses come back
   in the same order their requests were sent, per stream (true for
   HTTP/1.1 keep-alive without pipelining, which is what dynamo-fields'
   :request-method/:status pairing relies on) -- an event on a stream with
   no pending queue (e.g. a protocol that never registers a `request?`
   method) just passes through untouched."
  [events]
  (loop [[e & more] events, pending {}, acc (transient [])]
    (if-not e
      (persistent! acc)
      (let [stream (:stream e)]
        (cond
          (request? e)
          (let [drop? (noise? e)]
            (recur more (update pending stream (fnil conj []) drop?)
                   (cond-> acc (not drop?) (conj! e))))

          (contains? pending stream)
          (let [drop? (first (get pending stream))]
            (recur more (update pending stream (comp vec rest))
                   (cond-> acc (not drop?) (conj! e))))

          :else
          (recur more pending (conj! acc e)))))))
