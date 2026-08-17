(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is]]
            [clojure.string :as str]
            [fressian-decode]
            [tshark])
  (:import (java.util Arrays)))

; A raw tshark record carrying only the :tcp layer -- no :http or :memcache
; dissection -- like a bare TCP segment (e.g. Syn/Ack/Fin, or a segment whose
; payload didn't get reassembled into an upper-layer message yet).
(def tshark-record
  {:timestamp 1699999999123
   :layers {:tcp {:tcp_tcp_port             ["8000"]
                  :tcp_tcp_srcport          "54321"
                  :tcp_tcp_dstport          "8000"
                  :tcp_tcp_stream           "0"
                  :tcp_tcp_len              "0"
                  :tcp_tcp_payload          ""}}})

(def tshark-lines (for [contents [(slurp "/tmp/tshark.log")]
                        line (str/split-lines contents)
                        :let [tshark-record (charred/read-json line :key-fn keyword)]
                        :when (not (:index tshark-record))]
                    (update tshark-record :timestamp parse-long)))


(defn- some-vals
  "m with nil-valued entries dropped -- same helper tshark.clj's own
   some-vals is, for the same reason: an event map shouldn't carry keys
   that don't apply to it (e.g. :status on a request)."
  [m]
  (into (empty m) (remove (comp nil? val)) m))

(defn- hex-payload->bytes
  "tshark's colon-hex payload string (e.g. \"78:56:34:12\") as a vector of
   byte values (0-255) instead."
  [hex]
  (when (seq hex)
    (mapv #(Integer/parseInt % 16) (str/split hex #":"))))

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

(def ^:private flag-order [:URG :ACK :PSH :RST :SYN :FIN])

(defn- flags->tag [flags]
  (str/join "," (map name (filter flags flag-order))))

(defn tshark->tcp
  "A drawable event (see diagram/write-svg!): flat :timestamp/:srcport/
   :dstport/:protocol at the top level (:stream is also mirrored at the top
   level, alongside them, since that's what tshark/remove-noise's per-stream
   request/response pairing keys off), plus the fuller decoded detail
   (ports, stream, len, flags, payload) nested under :tcp. :tag/:note (the
   arrow label/note diagram.clj draws) aren't set here -- see `draw`."
  [record]
  (when-let [tcp (get-in record [:layers :tcp])]
    (let [ports (:tcp_tcp_port tcp)
          ports (if (sequential? ports) ports [ports])
          flags (tcp-flags tcp)
          src-port (parse-long (:tcp_tcp_srcport tcp))
          dst-port (parse-long (:tcp_tcp_dstport tcp))
          payload (byte-array (hex-payload->bytes (:tcp_tcp_payload tcp)))
          len (parse-long (:tcp_tcp_len tcp))
          stream (parse-long (:tcp_tcp_stream tcp))]
      [(assoc record
         :protocol :tcp
         :srcport src-port
         :dstport dst-port
         :stream stream
         :tcp {:ports    (into #{} (map parse-long) ports)
               :src-port src-port
               :dst-port dst-port
               :stream   stream
               :len      len
               :flags    flags
               :payload  payload})])))

(defn- ->vec
  "x already a sequential collection as-is, a single item wrapped in one, or
   [] for nil -- same normalization tshark.clj's own ->vec does for a
   :layers value that's sometimes one map, sometimes a vector of them."
  [x]
  (cond (nil? x) [] (sequential? x) (vec x) :else [x]))

(defn tshark-tcp->memcache
  "A seq of drawable events (see diagram/write-svg!), one per memcache PDU,
   given `tcp-event` -- one element of tshark->tcp's own output (its :layers
   passes straight through from the raw record via that fn's `assoc`, so
   :layers :memcache is still there to read). :layers :memcache can be a
   single map or a vector of several PDUs packed into one TCP segment (see
   tshark.clj's split-memcache-messages), so this walks them in order,
   accumulating each PDU's byte offset into the shared TCP payload already
   decoded by tshark->tcp. Layers the fuller semantic detail (:operation,
   :key, :status, :payload) on top, nested under :memcache. :tag/:note (the
   arrow label/note diagram.clj draws) aren't set here -- see `draw`."
  [tcp-event]
  (when-let [memcache (get-in tcp-event [:layers :memcache])]
    (let [payload  (get-in tcp-event [:tcp :payload])
          ms       (->vec memcache)
          pdu-lens (map #(+ 24 (parse-long (:memcache_memcache_total_body_length %))) ms)
          offsets  (reductions + 0 pdu-lens)]
      (for [[m offset] (map vector ms offsets)
            :let [total     (parse-long (:memcache_memcache_total_body_length m))
                  extras    (parse-long (:memcache_memcache_extras_length m))
                  key-len   (parse-long (:memcache_memcache_key_length m))
                  k         (:memcache_memcache_key m)
                  operation (tshark/opcode->command (parse-long (:memcache_memcache_opcode m)) :unknown)
                  status    (some->> (:memcache_memcache_status m) parse-long tshark/status->outcome)
                  from      (+ offset 24 extras key-len)
                  to        (+ offset 24 total)
                  payload   (when (and payload (< from to) (<= to (count payload)))
                              (Arrays/copyOfRange ^bytes payload (int from) (int to)))]]
        (assoc tcp-event
          :protocol :memcache
          :memcache {:operation operation
                     :key       k
                     :status    status
                     :payload   payload})))))

(defn- json-body
  "tshark's hex-encoded http.file_data, decoded from hex and JSON-parsed --
   nil if there's no body, or it doesn't parse as JSON."
  [http]
  (let [body-bytes (byte-array (hex-payload->bytes (:http_http_file_data http)))]
    (when (pos? (alength body-bytes))
      (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
           (catch Exception _ nil)))))

(defn- parse-headers
  "tshark's raw request-line strings (e.g. \"Host: localhost\") as a
   Ring-style headers map -- lowercased string keys, since that's what
   Ring's own header maps use."
  [lines]
  (into {}
        (keep (fn [line]
                (when-let [[_ k v] (re-matches #"(?s)([^:]+):\s*(.*)" (str line))]
                  [(str/lower-case (str/trim k)) (str/trim v)])))
        (->vec lines)))

(defn tshark-tcp->http
  "A drawable event (see diagram/write-svg!), given `tcp-event` -- one
   element of tshark->tcp's own output (see tshark-tcp->memcache's docstring
   for why :layers is still readable off it). :layers :http holds one HTTP
   request or response; layers its semantic fields on top as a Ring-style
   request/response map nested under :http (:request-method + :uri +
   :headers for a request, :status for a response, :body either way).
   :tag/:note (the arrow label/note diagram.clj draws) aren't set here --
   see `draw`."
  [tcp-event]
  (when-let [http (get-in tcp-event [:layers :http])]
    (let [request-method (some-> (:http_http_request_method http) str/lower-case keyword)
          uri            (:http_http_request_uri http)
          headers        (parse-headers (or (:http_http_request_line http)
                                            (:http_http_response_line http)))
          status         (some-> (:http_http_response_code http) parse-long)
          body           (json-body http)]
      [(assoc tcp-event
         :protocol :http
         :http     (some-vals
                     {:request-method request-method
                      :uri            uri
                      :headers        headers
                      :status         status
                      :body           body}))])))

(defn- dynamo-operation
  "DynamoDB's operation name, e.g. \"PutItem\" -- the part of the
   X-Amz-Target header after the service prefix."
  [headers]
  (some->> (get headers "x-amz-target")
           (re-find #"\.(\S+)$")
           second))

(defn- dynamo-key [body]
  (some-> (or (get-in body [:Item :id])
              (get-in body [:Key :id]))
          first val))

(defn http->dynamo
  "A drawable event (see diagram/write-svg!), given `http-event` -- one
   element of tshark-tcp->http's own output; only its already-decoded :http
   info (headers/status/body) is needed, so this doesn't touch the raw
   tshark record at all. Recognizes DynamoDB's shape on top of generic HTTP
   (the X-Amz-Target header naming the operation, AttributeValue-wrapped
   fields, Datomic's own :v blob encoding) and layers the fuller semantic
   detail (:operation, :key, :body) on top, nested under :dynamo. :tag/:note
   (the arrow label/note diagram.clj draws) aren't set here -- see `draw`."
  [http-event]
  (let [{:keys [headers body]} (:http http-event)
        operation (dynamo-operation headers)
        decoded   body
        k         (dynamo-key decoded)]
    [(assoc http-event
       :protocol :dynamodb
       :dynamo   (some-vals
                   {:operation operation
                    :key       k
                    :body      decoded}))]))

(defmulti draw
  "Given a drawable event (see diagram/write-svg!) whose semantic detail
   (:tcp/:memcache/:http/:dynamo) is already parsed and merged in, decides
   what diagram.clj should draw for it, returning `event` with :tag/:note
   added. Dispatches on :protocol -- the one place that decision lives.
   Called once, right before drawing (see the `comment` block below) -- not
   by the protocol parsers above."
  :protocol)

(defmethod draw :tcp [event]
  (assoc event
    :tag  (flags->tag (get-in event [:tcp :flags]))
    :note (String. (get-in event [:tcp :payload]))))

(defmethod draw :memcache [event]
  (assoc event
    :tag (str (name (get-in event [:memcache :operation])) " " (get-in event [:memcache :key]))
    :note (get-in event [:memcache :payload])))

(defmethod draw :http [event]
  (let [{:keys [request-method status body]} (:http event)]
    (assoc event
      :tag  (or (some-> request-method name str/upper-case) (str status))
      :note body)))

(defmethod draw :dynamodb [event]
  (let [{:keys [operation key body]} (:dynamo event)]
    (assoc event
      :tag  (if operation (str operation " " key) (str (get-in event [:http :status])))
      :note body)))

(defn- noisy?
  "Same call as tshark/default-noisy?, just reading the key from wherever
   it's nested here (:dynamo/:memcache) instead of a top-level :key --
   assumes the transactor's heartbeat/lease traffic is always a GetItem or
   PutItem on item id \"pod-coord\"."
  [event]
  (#{"pod-coord"} (get-in event [:dynamo :key])))

(defn- request? [event] (contains? tshark/protocol-ports (:dstport event)))

(defn remove-noise
  "Stateful transducer: drops requests matching `noisy?` -- a predicate over
   a request event, e.g. `#(= \"pod-coord\" (:key %))`, called only on
   requests, can be anything -- together with their paired response. Pairs
   requests to responses via a per-stream FIFO queue of pending verdicts (so
   a stream with several in-flight requests remembers each one in order);
   assumes responses come back in the same order their requests were sent,
   per stream. One pass over the seq, no need to hold it all in memory, and
   no metadata added to surviving events.

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
          (let [stream (:stream e)]
            (cond
              (request? e)
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

(defn- unpack-7bit-lsb [^String s]
  (let [n (count s)
        nbytes (quot (* 7 n) 8)
        out (byte-array nbytes)]
    (dotimes [i n]
      (let [c (long (.charAt s i)) bit-pos (* 7 i)]
        (dotimes [b 7]
          (when (bit-test c b)
            (let [pos (+ bit-pos b) byte-idx (quot pos 8) bit-in-byte (rem pos 8)]
              (when (< byte-idx nbytes)
                (aset out byte-idx (unchecked-byte (bit-or (bit-and 0xff (aget out byte-idx))
                                                           (bit-shift-left 1 bit-in-byte))))))))))
    out))
(defn update-in-if-present [m ks f]
  (if (not= ::missing (get-in m ks ::missing))
    (update-in m ks f)
    m))
(defn decode-datomic [event]
  (cond
    (seq (:payload (:memcache event)))
    (update-in event [:memcache :payload] fressian-decode/decode-body)

    (#{"pod-standby" "pod-coord"} (:S (:id (:Item (:body (:dynamo event))))))
    (update-in-if-present event [:dynamo :body :Item :key :S] edn/read-string)

    (some-> (:S (:id (:Item (:body (:dynamo event))))) parse-uuid)
    (update-in-if-present event [:dynamo :body :Item :v :S] (comp fressian-decode/decode-body unpack-7bit-lsb))

    :else event))

(comment
  (require '[diagram])
  (def tcp-events (mapcat tshark->tcp tshark-lines))
  (def memcache-events (mapcat tshark-tcp->memcache tcp-events))
  (def http-events (mapcat tshark-tcp->http tcp-events))
  (def dynamo-events (mapcat http->dynamo http-events))

  ;; remove-noise pairs a request to its response by :stream (a per-stream
  ;; FIFO), so it needs a single seq holding both dynamo's requests and
  ;; responses -- and in :timestamp order, same as draw-diagram!'s own
  ;; pipeline sorts before drawing.
  (def dynamo-events-quiet
    (remove-noise noisy? dynamo-events))

  (def events (map decode-datomic dynamo-events))

  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (def protocol-styles
    {:dynamodb {:color "#FFAEFB" :label "Storage (DynamoDB)"}
     :memcache {:color "#FDFF94" :label "Cache (memcached)"}
     :tcp      {:color "#D3D3D3" :label "TCP"}
     :http     {:color "#94C9FF" :label "HTTP"}})

  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (apply mapv vector form))
  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (apply mapv vector form))
  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (apply mapv vector form))

  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[v e a t added] form]
        (mapv #(zipmap [:e :a :v :t :added]  %&) e a v t added))))

  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[index-tdata segment-id _ datom-count] form]
        (mapv #(zipmap [:first-datom :seg-id :datom-count] %&) (:form index-tdata) segment-id datom-count))))

  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[index-tdata dir-id] form]
        (mapv #(zipmap [:first-datom :dir-id] %&) (:form index-tdata) dir-id))))

  ;; `draw` is called here, once, right before handing events to write-svg! --
  ;; not by any of the protocol parsers above.
  (diagram/write-svg! (map draw tcp-events) "/tmp/tcp.svg"
                      {:port-names port-names :protocol-styles protocol-styles})
  (diagram/write-svg! (map draw events) "/tmp/memcache.svg"
                      {:port-names port-names :protocol-styles protocol-styles})
  (diagram/write-svg! (map draw http-events) "/tmp/http.svg"
                      {:port-names port-names :protocol-styles protocol-styles})
  (diagram/write-svg! (map draw dynamo-events) "/tmp/dynamo.svg"
                      {:port-names port-names :protocol-styles protocol-styles})
  (diagram/write-svg! (map draw dynamo-events-quiet) "/tmp/dynamo-quiet.svg"
                      {:port-names port-names :protocol-styles protocol-styles})
  (diagram/write-svg! (map (comp draw decode-datomic) dynamo-events) "/tmp/events.svg"
                      {:port-names port-names :protocol-styles protocol-styles}))

