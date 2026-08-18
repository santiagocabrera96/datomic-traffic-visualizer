(ns tshark
  "Parses a tshark -T json capture log into TCP-layer events -- see
   read-tshark. `decode-protocol` is an open multimethod dispatching on
   protocol keyword; only :tcp (and :default, which just falls back to :tcp)
   are registered here. Adding a protocol means requiring its namespace and
   registering a `decode-protocol` defmethod for it -- see memcache.clj,
   http.clj, and dynamodb.clj, which each do exactly that for themselves."
  (:require [charred.api :as charred]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [utils :refer [hex-payload->bytes]]))

(def ^:private flag-field->keyword
  {:tcp_tcp_flags_syn   :SYN
   :tcp_tcp_flags_ack   :ACK
   :tcp_tcp_flags_fin   :FIN
   :tcp_tcp_flags_reset :RST
   :tcp_tcp_flags_push  :PSH
   :tcp_tcp_flags_urg   :URG})

(defn- tcp-flags
  "Which of tshark's tcp.flags.* booleans are set on this :tcp layer, as a
   set of keywords, e.g. #{:SYN} or #{:ACK :FIN}."
  [tcp]
  (into #{} (keep (fn [[field kw]] (when (true? (get tcp field)) kw))) flag-field->keyword))

(defn- tshark->tcp
  "Wrapped in a single-element vector (rather than returned bare) to match
   decode-protocol's 1->0/1->many contract, so read-tshark can mapcat over
   every method uniformly."
  [record]
  (when-let [tcp (get-in record [:layers :tcp])]
    (let [flags (tcp-flags tcp)
          src-port (parse-long (:tcp_tcp_srcport tcp))
          dst-port (parse-long (:tcp_tcp_dstport tcp))
          payload (byte-array (hex-payload->bytes (:tcp_tcp_payload tcp)))
          len (parse-long (:tcp_tcp_len tcp))
          stream (parse-long (:tcp_tcp_stream tcp))]
      [(assoc record
         :tcp {:src-port src-port
               :dst-port dst-port
               :stream   stream
               :len      len
               :flags    flags
               :payload  payload})])))

(defmulti decode-protocol
  "Open dispatch on protocol keyword, e.g. :memcache/:http/:dynamodb -- see
   read-tshark's :port->protocol. Adding a protocol is registering a
   defmethod for it; :tcp and :default (a plain :tcp fallback) are the only
   ones registered here."
  (fn [protocol _record] protocol))

(defmethod decode-protocol :tcp [_ record]
  (tshark->tcp record))

(defmethod decode-protocol :default [_ record]
  (decode-protocol :tcp record))

(defn read-tshark
  "Parse tshark lines from `f`, but will guess the server port and parse the
  timestamp. Keyword args:
    :port->protocol  (fn [server-port] protocol) -- when given, decode-protocol
                     is called on each record according to its server-port's
                     protocol, flattening 1->0/1->many results; when omitted,
                     raw records (with :server-port/:timestamp added) are
                     returned as-is
    :since           epoch-millis lower bound (inclusive) -- records
                     timestamped before it are dropped
    :until           epoch-millis upper bound (inclusive) -- records
                     timestamped after it are dropped"
  [f & {:keys [port->protocol since until]}]
  (let [contents (if (.exists (io/file f)) (slurp f) f)
        records (for [line (str/split-lines contents)
                      :let [tshark-record (charred/read-json line :key-fn keyword)]
                      ;; tshark's -T ek (bulk/Elasticsearch) json emits an
                      ;; {:index ...} pseudo-record before each real one --
                      ;; skip those rather than fail parsing them as packets
                      :when (not (:index tshark-record))
                      :let [tcp (:tcp (:layers tshark-record))
                            server-port (min (parse-long (:tcp_tcp_srcport tcp))
                                             (parse-long (:tcp_tcp_dstport tcp)))
                            tshark-record (-> tshark-record
                                              (update :timestamp parse-long)
                                              (assoc :server-port server-port))]
                      :when (and (or (nil? since) (>= (:timestamp tshark-record) since))
                                 (or (nil? until) (<= (:timestamp tshark-record) until)))]
                  tshark-record)]
    (if port->protocol
      (mapcat #(decode-protocol (port->protocol (:server-port %)) %) records)
      (mapcat #(decode-protocol :tcp %) records))))

(defn remove-noise
  "Stateful transducer: drops requests matching `noisy?` -- a predicate over
   a request event, e.g. `#(= \"pod-coord\" (:key %))`, called only on
   requests, can be anything -- together with their paired response. Pairs
   requests to responses via a per-stream FIFO queue of pending verdicts (so
   a stream with several in-flight requests remembers each one in order);
   assumes responses come back in the same order their requests were sent,
   per stream. One pass over the seq, no need to hold it all in memory, and
   no metadata added to surviving events. An event counts as a request when
   its `:server-port` (see read-tshark) matches its own :tcp :dst-port,
   response otherwise.

   Called with just `noisy?`, returns the transducer, for composing into a
   larger `comp` chain; called with `noisy?` and a seq of events, applies it
   directly and returns the resulting (lazy) seq -- same two-arity
   convention as `clojure.core/map`/`filter`/etc."
  ([noisy?]
   (fn [rf]
     (let [pending (volatile! {})]
       (fn
         ([] (rf))
         ([result] (rf result))
         ([result e]
          (let [stream (:stream (:tcp e))]
            (cond
              (= (:server-port e) (:dst-port (:tcp e)))
              (let [drop? (boolean (noisy? e))]
                (vswap! pending update stream (fnil conj []) drop?)
                (if drop? result (rf result e)))

              (contains? @pending stream)
              (let [drop? (first (get @pending stream))]
                (vswap! pending update stream (comp vec rest))
                (if drop? result (rf result e)))

              :else
              (rf result e))))))))
  ([noisy? events] (sequence (remove-noise noisy?) events)))

(comment
  ;; A minimal capture: one TCP record, no protocol decoding -- decode-protocol
  ;; falls back to :default (== :tcp) for any record when :port->protocol
  ;; isn't given. read-tshark accepts either a path or the raw contents
  ;; themselves (checked via io/file's .exists), so no capture file is needed
  ;; here.
  (require '[charred.api :as charred] '[clojure.string :as str])
  (def sample-log
    (->> [{:timestamp "1"
           :layers    {:tcp {:tcp_tcp_srcport "123"
                             :tcp_tcp_dstport "12"
                             :tcp_tcp_payload "00:01"
                             :tcp_tcp_len     "2"
                             :tcp_tcp_stream  "1"}}}]
         (map charred/write-json-str)
         (str/join "\n")))
  (read-tshark sample-log)

  ;; Only events after `since` (e.g. a session's start time, to skip
  ;; startup noise) or before `until`.
  (read-tshark sample-log :since (- (System/currentTimeMillis) 10000000))

  ;; Implementing a new protocol is a defmethod, wherever it's convenient to
  ;; put it -- own namespace (see memcache.clj/http.clj/dynamodb.clj), the
  ;; consuming code, a REPL scratch buffer. Here inline, dispatching on a
  ;; made-up port and cleaning up after itself with remove-method.
  (defmethod decode-protocol :pepe [_ record]
    [(assoc record :pepe {:hello :world})])
  (read-tshark sample-log :port->protocol {12 :pepe})
  (remove-method decode-protocol :pepe)

  ;; Registering memcache/http/dynamodb (each registers its own
  ;; decode-protocol method on require -- see their namespaces) lets
  ;; read-tshark dispatch each record by its guessed :server-port.
  (require '[memcache] '[http] '[dynamodb])
  (def events (read-tshark sample-log :port->protocol {8000 :dynamodb 11211 :memcache}))

  ;; Drops a noisy request (and its paired response) per stream, e.g. the
  ;; transactor's pod-coord heartbeat.
  (remove-noise (comp #{"pod-coord"} :key :dynamodb) events)

  ;; remove-noise pairs by (:stream (:tcp e)), not any top-level :stream --
  ;; hand-build two synthetic requests + responses on *different* streams to
  ;; see it drop only the matching pair and leave the other stream be. An
  ;; event counts as a request when its :server-port equals its own :tcp
  ;; :dst-port (see read-tshark for how :server-port is guessed).
  (let [noisy-req    {:server-port 8000 :tcp {:dst-port 8000 :stream 1} :dynamodb {:key "pod-coord"}}
        noisy-resp   {:server-port 8000 :tcp {:dst-port 55111 :stream 1}}
        quiet-req    {:server-port 8000 :tcp {:dst-port 8000 :stream 2} :dynamodb {:key "item/42"}}
        quiet-resp   {:server-port 8000 :tcp {:dst-port 55222 :stream 2}}]
    (remove-noise (comp #{"pod-coord"} :key :dynamodb)
                  [noisy-req quiet-req noisy-resp quiet-resp])
    ;; => (quiet-req quiet-resp) -- the pod-coord pair on stream 1 is gone,
    ;;    stream 2's pair survives untouched.
    ))
