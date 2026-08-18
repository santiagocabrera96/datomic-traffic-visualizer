(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [fressian-decode]
            [tshark]
            [utils :refer [some-vals hex-payload->bytes update-in-if-present unpack-7bit-lsb]])
  (:import (java.util Arrays)))

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

(defn tshark->tcp [record]
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
  (let [{{memcache :memcache} :layers
         {payload :payload}   :tcp} tcp-event
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
        :type     :memcache
        :memcache {:operation operation
                   :key       k
                   :status    status
                   :payload   payload}))))

(defn- json-body
  "bytes decoded as JSON -- nil if empty, or it doesn't parse as JSON."
  [^bytes body-bytes]
  (when (and body-bytes (pos? (alength body-bytes)))
    (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
         (catch Exception _ nil))))

(defn- parse-headers [lines]
  (into {}
        (keep (fn [line]
                (when-let [[_ k v] (re-matches #"(?s)([^:]+):\s*(.*)" (str line))]
                  [(str/lower-case (str/trim k)) (str/trim v)])))
        (->vec lines)))

(defn- json-content-type? [headers]
  (boolean (some->> (get headers "content-type") (re-find #"(?i)json"))))

(defn tshark-tcp->http [tcp-event]
  (let [{{http :http} :layers} tcp-event]
    (let [request-method (some-> (:http_http_request_method http) str/lower-case keyword)
          uri            (:http_http_request_uri http)
          headers        (parse-headers (or (:http_http_request_line http)
                                            (:http_http_response_line http)))
          status         (some-> (:http_http_response_code http) parse-long)
          body-bytes     (byte-array (hex-payload->bytes (:http_http_file_data http)))
          body           (when (json-content-type? headers) (json-body body-bytes))]
      (assoc tcp-event
        :type :http
        :http (some-vals
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
      :type :dynamodb
      :dynamodb (some-vals
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
  "Given an event (:tcp/:memcache/:http/:dynamo) is already parsed and merged in, decides
   what diagram.clj should draw for it, returning `event` with :tag/:note/:color
   added. Dispatches on :type."
  :type)

(defmethod draw :tcp [event]
  (let [{:keys [flags payload]} (:tcp event)]
    (assoc event
      :tag (str/join "," (map name (filter flags [:URG :ACK :PSH :RST :SYN :FIN])))
      :note (String. payload)
      :color "#D3D3D3")))

(defmethod draw :memcache [event]
  (let [{:keys [key operation payload]} (:memcache event)]
    (when key (def event event))
    (assoc event
      :tag (str (name operation) " " key)
      :note payload
      :color "#FDFF94")))

(defmethod draw :http [event]
  (let [{:keys [request-method uri status headers body]} (:http event)]
    (assoc event
      :tag  (or (some-> request-method name str/upper-case (str " " uri)) (str status))
      :note {:headers headers
             :body body}
      :color "#94C9FF")))

(defmethod draw :dynamodb [event]
  (let [{:keys [operation key body status]} (:dynamodb event)]
    (assoc event
      :tag  (if operation (str operation " " key) (str status))
      :note body
      :color "#FFAEFB")))

(defn attach-participants
  "Adds :from/:to to each event, naming its :tcp src-port/dst-port via
   `port->name` -- a port missing from it becomes :unknown-<port>."
  [port->name event]
  (let [{:keys [src-port dst-port]} (:tcp event)]
    (assoc event
      :from (port->name src-port (keyword (str "unknown-" src-port)))
      :to   (port->name dst-port (keyword (str "unknown-" dst-port))))))

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

(defn decode-datomic [event]
  (cond
    (seq (:payload (:memcache event)))
    (update-in event [:memcache :payload] fressian-decode/decode-body)

    (#{"pod-standby" "pod-coord"} (:S (:id (:Item (:body (:dynamodb event))))))
    (update-in-if-present event [:dynamodb :body :Item :key :S] edn/read-string)

    (some-> (:S (:id (:Item (:body (:dynamodb event))))) parse-uuid)
    (update-in-if-present event [:dynamodb :body :Item :v :S] (comp fressian-decode/decode-body unpack-7bit-lsb))

    :else event))

(comment
  (require '[diagram])

  ; Ignore the following 10 lines
  ; Parts: Parse tshark with tcp protocol
  ; Make event to something that can be drawn in sequence diagram, should contain tag, note, from, to, and color. The legend is another parameter.
  ; Take all those drawable things and take the src/dst port and tag them with a usable label.
  ; Parse datomic known shapes
  ; fressian decode
  ; utils
  ; Finally putting it all together.

  (defn read-tshark
    "Parse tshark lines, but will guess the server port and parse the timestamp.
    If given a port->protocol function, it will call decode-protocol according to
    the protocol of the server-port of the call."
    ([f]
     (for [line (str/split-lines (slurp f))
           :let [tshark-record (charred/read-json line :key-fn keyword)]
           :when (not (:index tshark-record))
           :let [tcp (:tcp (:layers tshark-record))
                 server-port (min (parse-long (:tcp_tcp_srcport tcp))
                                  (parse-long (:tcp_tcp_dstport tcp)))
                 tshark-record (-> tshark-record
                                   (update :timestamp parse-long)
                                   (assoc :server-port server-port))]]
       tshark-record))
    ([port->protocol f]
     (mapcat #(decode-protocol (port->protocol (:server-port %)) %) (read-tshark f))))

  (read-tshark "/tmp/tshark.log")
  (def tshark-records (read-tshark {8000 :dynamodb
                                    11211 :memcache} "/tmp/tshark.log"))
  (def events
    (->> tshark-records
         (remove-noise (comp #{"pod-coord"} :key :dynamodb))
         (map decode-datomic)))
  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (def regions (clojure.edn/read-string (slurp "/tmp/tshark.log.regions.edn")))
  (def legend
    [{:color "#FFAEFB" :label "Storage (DynamoDB)"}
     {:color "#FDFF94" :label "Cache (memcached)"}
     {:color "#D3D3D3" :label "TCP"}
     {:color "#94C9FF" :label "HTTP"}])

  ; Regions, needed and orthogonal, is naming sections of the diagram by timestamp.
  ; port->name, optional, not needed
  (diagram/write-svg! (map (comp draw (partial attach-participants port-names)) events) "/tmp/tshark.log.svg"
                      {:port-names port-names :regions regions :legend legend})


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
                      {:port-names port-names :legend legend}))

