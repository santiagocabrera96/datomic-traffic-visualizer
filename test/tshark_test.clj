(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.test :refer [deftest is]]
            [clojure.string :as str]
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
   :dstport/:protocol/:tag at the top level (:tag/:note are the arrow
   label/note diagram.clj draws), plus the fuller decoded detail (ports,
   stream, len, flags, payload) nested under :tcp."
  [record]
  (when-let [tcp (get-in record [:layers :tcp])]
    (let [ports (:tcp_tcp_port tcp)
          ports (if (sequential? ports) ports [ports])
          flags (tcp-flags tcp)
          src-port (parse-long (:tcp_tcp_srcport tcp))
          dst-port (parse-long (:tcp_tcp_dstport tcp))
          payload (byte-array (hex-payload->bytes (:tcp_tcp_payload tcp)))
          len (parse-long (:tcp_tcp_len tcp))]
      [(assoc record
         :protocol :tcp
         :srcport src-port
         :dstport dst-port
         :tag (flags->tag flags)
         :note payload
         :tcp {:ports    (into #{} (map parse-long) ports)
               :src-port src-port
               :dst-port dst-port
               :stream   (parse-long (:tcp_tcp_stream tcp))
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
   decoded by tshark->tcp. Layers the memcache-specific fields on top: :tag
   (the command, e.g. :get/:set) at the top level (for diagram.clj's arrow
   label), :note (the value bytes, sliced out of the PDU's own span past its
   24-byte header + extras + key) for its note, plus the fuller semantic
   detail (:operation, :key, :status, :payload) nested under :memcache."
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
          :protocol  :memcache
          :tag       operation
          :note      payload
          :memcache  {:operation operation
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
   :headers for a request, :status for a response, :body either way), plus
   :tag/:note at the top level for diagram.clj's arrow label/note."
  [tcp-event]
  (when-let [http (get-in tcp-event [:layers :http])]
    (let [request-method (some-> (:http_http_request_method http) str/lower-case keyword)
          uri            (:http_http_request_uri http)
          headers        (parse-headers (or (:http_http_request_line http)
                                            (:http_http_response_line http)))
          status         (some-> (:http_http_response_code http) parse-long)
          body           (json-body http)]
      [(assoc tcp-event
         :protocol  :http
         :tag       (or (some-> request-method name str/upper-case)
                        (str status))
         :note      body
         :http      (some-vals
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
   fields, Datomic's own :v blob encoding) and layers it on top: :tag/:note
   at the top level for diagram.clj's arrow label/note, plus the fuller
   semantic detail (:operation, :key, :body) nested under :dynamo."
  [http-event]
  (let [{:keys [headers status body]} (:http http-event)
        operation (dynamo-operation headers)
        decoded   body
        k         (dynamo-key decoded)]
    [(assoc http-event
       :protocol :dynamodb
       :tag      (if operation (str operation " " k) (str status))
       :note     decoded
       :dynamo   (some-vals
                   {:operation operation
                    :key       k
                    :body      decoded}))]))

(comment
  (require '[diagram])
  (def tcp-events (mapcat tshark->tcp tshark-lines))
  (def memcache-events (mapcat tshark-tcp->memcache tcp-events))
  (def http-events (mapcat tshark-tcp->http tcp-events))
  (def dynamo-events (mapcat http->dynamo http-events))


  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (diagram/write-svg! tcp-events "/tmp/tcp.svg"
                      {:port-names port-names})
  (diagram/write-svg! memcache-events "/tmp/memcache.svg"
                      {:port-names port-names})
  (diagram/write-svg! http-events "/tmp/http.svg"
                      {:port-names port-names})
  (diagram/write-svg! dynamo-events "/tmp/dynamo.svg"
                      {:port-names port-names}))

