(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is]]
            [clojure.string :as str]
            [fressian-decode]
            [tshark])
  (:import (java.util Arrays)))

; TODO: Move to utils namespace
(defn- some-vals
  "m with nil-valued entries dropped -- same helper tshark.clj's own
   some-vals is, for the same reason: an event map shouldn't carry keys
   that don't apply to it (e.g. :status on a request)."
  [m]
  (into (empty m) (remove (comp nil? val)) m))

; TODO: Move to utils namespace
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

(defn tshark->tcp [record]
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
  [x]
  (cond (nil? x) [] (sequential? x) (vec x) :else [x]))

(def opcode->command
  {0x00 :get 0x01 :set 0x02 :add 0x03 :replace 0x04 :delete 0x05 :incr 0x06 :decr
   0x07 :quit 0x08 :flush-all 0x09 :get 0x0b :version 0x0c :get 0x0d :get
   0x0e :append 0x0f :prepend 0x10 :stats 0x11 :set 0x12 :add 0x13 :replace
   0x14 :delete 0x15 :incr 0x16 :decr 0x17 :quit 0x18 :flush-all 0x19 :append
   0x1a :prepend 0x1b :verbosity 0x1c :touch 0x1d :gat 0x1e :gat})
(def status->outcome
  {0x00 :ok
   0x01 :not-found
   0x02 :exists
   0x03 :server-error
   0x04 :client-error
   0x05 :not-stored
   0x06 :client-error
   0x81 :error
   0x82 :server-error
   0x83 :server-error})
(defn tshark-tcp->memcache [tcp-event]
  (let [{{memcache           :memcache
          {payload :payload} :tcp} :layers} tcp-event
        ms       (->vec memcache)
        pdu-lens (map #(+ 24 (parse-long (:memcache_memcache_total_body_length %))) ms)
        offsets  (reductions + 0 pdu-lens)]
    (for [[m offset] (map vector ms offsets)
          :let [total     (parse-long (:memcache_memcache_total_body_length m))
                extras    (parse-long (:memcache_memcache_extras_length m))
                key-len   (parse-long (:memcache_memcache_key_length m))
                k         (:memcache_memcache_key m)
                operation (opcode->command (parse-long (:memcache_memcache_opcode m)) :unknown)
                status    (some->> (:memcache_memcache_status m) parse-long status->outcome)
                from      (+ offset 24 extras key-len)
                to        (+ offset 24 total)
                payload   (when (and payload (< from to) (<= to (count payload)))
                            (Arrays/copyOfRange ^bytes payload (int from) (int to)))]]
      (assoc tcp-event
        :protocol :memcache
        :memcache {:operation operation
                   :key       k
                   :status    status
                   :payload   payload}))))

(defn- json-body
  "tshark's hex-encoded http.file_data, decoded from hex and JSON-parsed --
   nil if there's no body, or it doesn't parse as JSON."
  [http]
  ; TODO: This function should be called with the byte-array directly to be usable elsewhere.
  (let [body-bytes (byte-array (hex-payload->bytes (:http_http_file_data http)))]
    (when (pos? (alength body-bytes))
      (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
           (catch Exception _ nil)))))

(defn- parse-headers [lines]
  (into {}
        (keep (fn [line]
                (when-let [[_ k v] (re-matches #"(?s)([^:]+):\s*(.*)" (str line))]
                  [(str/lower-case (str/trim k)) (str/trim v)])))
        (->vec lines)))

(defn tshark-tcp->http [tcp-event]
  (let [{{http :http} :layers} tcp-event]
    (let [request-method (some-> (:http_http_request_method http) str/lower-case keyword)
          uri            (:http_http_request_uri http)
          headers        (parse-headers (or (:http_http_request_line http)
                                            (:http_http_response_line http)))
          status         (some-> (:http_http_response_code http) parse-long)
          ; TODO: Parse of body as json should only be made if the content-type header is json related.
          body           (json-body http)]
      (assoc tcp-event
        :protocol :http
        :http     (some-vals
                    {:request-method request-method
                     :uri            uri
                     :headers        headers
                     :status         status
                     :body           body})))))

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

(defn http->dynamo [http-event]
  (let [{:keys [headers body status]} (:http http-event)
        operation (dynamo-operation headers)
        decoded   body
        k         (dynamo-key decoded)]
    (assoc http-event
      :protocol :dynamodb
      :dynamo   (some-vals
                  {:operation operation
                   :key       k
                   :status    status
                   :body      decoded}))))

(defmulti decode-protocol
  (fn [protocol _record] protocol))

(defmethod decode-protocol :tcp [_ record]
  (tshark->tcp record))

(defmethod decode-protocol :memcache [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :memcache :layers))
       (mapcat tshark-tcp->memcache)))

(defmethod decode-protocol :http [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :http :layers))
       (map tshark-tcp->http)))

(defmethod decode-protocol :dynamodb [_ record]
  (map http->dynamo (decode-protocol :http record)))

(defmulti draw
  "Given a drawable event (see diagram/write-svg!) whose semantic detail
   (:tcp/:memcache/:http/:dynamo) is already parsed and merged in, decides
   what diagram.clj should draw for it, returning `event` with :tag/:note
   added. Dispatches on :protocol -- the one place that decision lives.
   Called once, right before drawing (see the `comment` block below) -- not
   by the protocol parsers above."
  :protocol)

(defn- flags->tag [flags]
  (str/join "," (map name (filter flags flag-order))))
(defmethod draw :tcp [event]
  (let [{:keys [flags payload]} (:tcp event)]
    (assoc event
      :tag (flags->tag flags)
      :note (String. payload))))

(defmethod draw :memcache [event]
  (let [{:keys [key operation payload]} (:memcache event)]
    (assoc event
      :tag (str (name operation) " " key)
      :note payload)))

(defmethod draw :http [event]
  (let [{:keys [request-method uri status headers body]} (:http event)]
    (assoc event
      :tag  (or (some-> request-method name str/upper-case (str " " uri)) (str status))
      :note {:headers headers
             :body body})))

(defmethod draw :dynamodb [event]
  (let [{:keys [operation key body status]} (:dynamo event)]
    (assoc event
      :tag  (if operation (str operation " " key) (str status))
      :note body)))

; TODO: remove-noise should receive the protocol-ports as parameter to pass to request? Or inline the call.
; TODO: rename :dstport keyword usage to be dst-port.
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

; TODO: Move to utils namespace
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
; TODO: Move to utils namespace
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

(defn tshark->protocol [event server-ports]
  (let [{{{src-port :tcp_tcp_srcport
           dst-port :tcp_tcp_dstport} :tcp} :layers} event]
    (or (server-ports (parse-long src-port))
        (server-ports (parse-long dst-port)))))

(comment
  (require '[diagram])

  (def server-ports
    {8000 :dynamodb
     11211 :memcache})

  (defn- noisy? [event]
    (#{"pod-coord"} (get-in event [:dynamo :key])))

  (def tshark-lines (for [contents [(slurp "/tmp/tshark.log")]
                          line (str/split-lines contents)
                          :let [tshark-record (charred/read-json line :key-fn keyword)]
                          :when (not (:index tshark-record))]
                      (update tshark-record :timestamp parse-long)))

  (def events
    (->> tshark-lines
         (mapcat #(decode-protocol (tshark->protocol % {8000 :http
                                                        11211 :memcache}) %))
         (remove-noise noisy?)
         (map decode-datomic)))

  (diagram/write-svg! (map draw events) "/tmp/tshark.log.svg"
                      {:port-names port-names :protocol-styles protocol-styles})

  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (def protocol-styles
    {:dynamodb {:color "#FFAEFB" :label "Storage (DynamoDB)"}
     :memcache {:color "#FDFF94" :label "Cache (memcached)"}
     :tcp      {:color "#D3D3D3" :label "TCP"}
     :http     {:color "#94C9FF" :label "HTTP"}})

  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (tagged-literal (symbol tag) form))
  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (tagged-literal (symbol tag) form))
  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (tagged-literal (symbol tag) form))

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
  (diagram/write-svg! (map draw events) "/tmp/tshark.log.svg"
                      {:port-names port-names :protocol-styles protocol-styles}))

