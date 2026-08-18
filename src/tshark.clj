(ns tshark
  "Turns a tshark capture log into decoded Datomic-traffic events and an SVG
   sequence diagram -- see draw-diagram!. Understands known protocols
   (dynamodb over http, memcache over tcp), splits grouped packets into
   individual protocol messages, decodes bytearrays (7-bit LSB packed
   strings, or hex strings like \"XX:XX:XX:XX\"), and fressian/edn-decodes
   their bodies."
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.walk :as walk]
            [diagram :as diagram]
            [fressian-decode]
            [utils :refer [some-vals hex-payload->bytes update-in-if-present unpack-7bit-lsb]]))

(def ^:private flag-field->keyword
  {:tcp_tcp_flags_syn   :SYN
   :tcp_tcp_flags_ack   :ACK
   :tcp_tcp_flags_fin   :FIN
   :tcp_tcp_flags_reset :RST
   :tcp_tcp_flags_push  :PSH
   :tcp_tcp_flags_urg   :URG})

(defn- tcp-flags
  "Which of tshark's tcp.flags.* booleans are set on this :tcp layer, as a
   set of keywords, e.g. #{:syn} or #{:ack :fin}."
  [tcp]
  (into #{} (keep (fn [[field kw]] (when (true? (get tcp field)) kw))) flag-field->keyword))

(defn- tshark->tcp [record]
  (when-let [tcp (get-in record [:layers :tcp])]
    (let [flags (tcp-flags tcp)
          src-port (parse-long (:tcp_tcp_srcport tcp))
          dst-port (parse-long (:tcp_tcp_dstport tcp))
          payload (byte-array (hex-payload->bytes (:tcp_tcp_payload tcp)))
          len (parse-long (:tcp_tcp_len tcp))
          stream (parse-long (:tcp_tcp_stream tcp))]
      [(assoc record
         :type :tcp
         :tcp {:src-port src-port
               :dst-port dst-port
               :stream   stream
               :len      len
               :flags    flags
               :payload  payload})])))

(defmulti decode-protocol (fn [protocol _record] protocol))

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
   no metadata added to surviving events. `server-ports` is the same
   port->protocol map passed to `tag-protocol` -- its keys are the
   destination ports whose events count as requests (see `request?`).

   Called with `server-ports` and `noisy?`, returns the transducer, for
   composing into a larger `comp` chain; called with `server-ports`,
   `noisy?`, and a seq of events, applies it directly and returns the
   resulting (lazy) seq -- same two-arity convention as
   `clojure.core/map`/`filter`/etc."
  ([noisy?]
   (fn [rf]
     (let [pending (volatile! {})]
       (fn
         ([] (rf))
         ([result] (rf result))
         ([result e]
          (let [stream (:stream e)]
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
  ; TODO: Update Rich comment block.
  (draw-diagram! "/tmp/tshark.log")
  (draw-diagram! "/tmp/tshark.log" {:svg-path "/tmp/events.svg"})
  (draw-diagram! "/tmp/tshark.log" {:noisy? (constantly false)})
  (draw-diagram! "/tmp/tshark.log" {:port-names {49515 :peer}})
  (draw-diagram! "/tmp/tshark.log" {:since (- (System/currentTimeMillis) 10000000)})

  ;; The decoded event maps draw-diagram! would otherwise turn straight into
  ;; an SVG -- handy at the REPL to inspect/filter/tally without generating
  ;; a diagram at all.
  (def events (with-open [rdr (io/reader "/tmp/tshark.log")]
                (->> (line-seq rdr) (parse-tshark nil) (parse-datomic-traffic) (into []))))
  (frequencies (map :protocol events)))
