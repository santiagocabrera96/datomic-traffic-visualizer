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
            [clojure.walk :as walk]
            [diagram :as diagram]
            [fressian-decode]))

(def protocols
  {:dynamodb {:port "8000"  :layer :http}
   :memcache {:port "11211" :layer :memcache}})

; Utils
(defn- some-vals [m]
  (into (empty m) (remove (comp nil? val)) m))
(defn- ->vec [x]
  (cond (nil? x) [] (sequential? x) (vec x) :else [x]))
(defn match-protocol
  "Which of `protocols` this record belongs to: port matches AND that
   protocol's layer is actually present -- excludes TCP segments that share
   the port but carry no dissected payload of their own."
  [record]
  (let [ports  (set (get-in record [:layers :tcp :tcp_tcp_port]))
        layers (:layers record)]
    (some (fn [[proto {:keys [port layer]}]]
            (when (and (ports port) (contains? layers layer))
              proto))
          protocols)))
(defn- hex->bytes ^bytes [^String hex]
  (if (empty? hex)
    (byte-array 0)
    (let [n   (quot (inc (.length hex)) 3)]
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
(defn- ->long [x] (when x (parse-long (str x))))
(defn decode-edn
  "Parses any string that looks like edn into its value, leaving everything
   else (including strings that fail to parse) untouched."
  [x]
  (walk/postwalk
    (fn [v]
      (if (string? v)
        (let [parsed (try (edn/read-string v) (catch Exception _ v))]
          (if (coll? parsed) parsed v))
        v))
    x))

; --- HTTP layer: generic request/response shape, no dynamo/datomic knowledge ---

(defn- json-body [^bytes body-bytes]
  (when (and body-bytes (pos? (alength body-bytes)))
    (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
         (catch Exception _ nil))))
(defn- http-fields
  "The protocol-agnostic parts of one HTTP request/response: its raw
   request-line headers (for callers to pick AWS-style X-Amz-* headers out
   of), status code, and JSON-decoded body -- no AttributeValue-unwrapping
   or other dynamo-specific shape imposed yet."
  [http]
  {:request-method (:http_http_request_method http)
   :request-line   (->vec (:http_http_request_line http))
   :status         (->long (:http_http_response_code http))
   :body           (json-body (:http_http_file_data http))})

; --- DynamoDB specifics: the AWS API shape layered on top of HTTP/JSON ---

(defn- dynamo-operation
  "DynamoDB's operation name, e.g. \"PutItem\" -- the part of the
   X-Amz-Target request-line header after the service prefix."
  [request-line]
  (some #(second (re-find #"(?i)^X-Amz-Target:\s*\S+\.(\S+)\s*$" (str %)))
        request-line))
(defn- attribute-value? [x]
  (and (map? x) (= 1 (count x))
       (contains? #{:S :N :B :BOOL :NULL :SS :NS :BS :M :L} (ffirst x))))
(defn- unwrap-attribute-value [{:keys [S N B BOOL NULL SS NS BS M L] :as av}]
  (cond
    S S
    N N
    B (.decode (java.util.Base64/getDecoder) ^String B)
    BOOL BOOL
    NULL nil
    SS SS
    NS NS
    BS (mapv #(.decode (java.util.Base64/getDecoder) ^String %) BS)
    M M
    L L))
(defn unwrap-attribute-values [x]
  (walk/postwalk (fn [v] (if (attribute-value? v) (unwrap-attribute-value v) v)) x))
(defn- dynamo-key [body]
  (or (get-in body [:Item :id])
      (get-in body [:Key :id])))
(defn dynamo-fields
  [{:keys [timestamp layers]}]
  (let [{:keys [tcp http]} layers
        {:keys [request-method request-line status body]} (http-fields http)
        body (unwrap-attribute-values body)]
    (some-vals {:protocol       :dynamodb
                :timestamp      timestamp
                :stream         (->long (:tcp_tcp_stream tcp))
                :srcport        (->long (:tcp_tcp_srcport tcp))
                :dstport        (->long (:tcp_tcp_dstport tcp))
                :request-method request-method
                :operation      (dynamo-operation request-line)
                :key            (dynamo-key body)
                :status         status
                :body           body})))

; --- Datomic-over-DynamoDB specifics: Datomic's own :v blob encoding, on top
; of dynamo-fields' already-AttributeValue-unwrapped body ---

(defn- ascii7-string? [^String s] (every? #(< (int %) 128) s))

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

(defn decode-dynamo-body
  "Datomic-specific: decode the 7-bit-packed gzip+fressian (or plain
   edn-printed) :v blob Datomic's dynamo backend writes into its
   AttributeValue strings. Takes body already JSON-parsed and
   AttributeValue-unwrapped (see dynamo-fields)."
  [body]
  (when body
    (walk/postwalk
      (fn [v]
        (if (and (string? v) (ascii7-string? v))
          (let [unpacked (unpack-7bit-lsb v)]
            (cond
              (fressian-decode/fressian-body? unpacked)
              (try (fressian-decode/decode-body unpacked) (catch Exception _ v))

              :else
              (let [parsed (some-> (String. unpacked)
                                   (as-> text (try (edn/read-string text) (catch Exception _ nil))))]
                (if (coll? parsed) parsed v))))
          v))
      body)))

; --- memcache: PDU splitting, opcode/status lookup tables, field extraction ---

(defn split-memcache-messages
  "One tshark packet record, possibly carrying several memcache PDUs packed
   into a single TCP segment, split into one record per PDU. Each result
   looks like an independent single-PDU packet: :layers :memcache is that
   PDU's map (never a vector), and :tcp_payload is narrowed to just that
   PDU's own bytes (24-byte header + its total_body_length), not the whole
   segment."
  [{:keys [layers] :as record}]
  (let [{:keys [tcp memcache]} layers
        ms      (->vec memcache)
        payload (:tcp_payload tcp)]
    (if (<= (count ms) 1)
      [record]
      (first
        (reduce (fn [[acc offset] m]
                  (let [pdu-len   (+ 24 (->long (:memcache_memcache_total_body_length m)))
                        pdu-bytes (java.util.Arrays/copyOfRange payload offset (+ offset pdu-len))]
                    [(conj acc (-> record
                                   (assoc-in [:layers :memcache] m)
                                   (assoc-in [:layers :tcp :tcp_payload] pdu-bytes)))
                     (+ offset pdu-len)]))
                [[] 0]
                ms)))))

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
(defn memcache-fields
  "The subset of one raw tshark memcache packet record that memcache needs.
   :memcache_memcache_key/:memcache_memcache_status only show up on some
   opcodes -- absent otherwise, which is fine, they're optional here."
  [{:keys [timestamp layers]}]
  (let [{:keys [tcp memcache]} layers]
    (let [payload-bytes (:tcp_payload tcp)
          total (->long (:memcache_memcache_total_body_length memcache))
          extras (->long (:memcache_memcache_extras_length memcache))
          key-len (->long (:memcache_memcache_key_length memcache))
          from (+ 24 extras key-len)
          to (+ 24 total)]
      (some-vals
        {:protocol  :memcache
         :timestamp timestamp
         :stream    (->long (:tcp_tcp_stream tcp))
         :srcport   (->long (:tcp_tcp_srcport tcp))
         :dstport   (->long (:tcp_tcp_dstport tcp))
         :operation (opcode->command (->long (:memcache_memcache_opcode memcache)) :unknown)
         :status    (status->outcome (->long (:memcache_memcache_status memcache)))
         :key       (:memcache_memcache_key memcache)
         :body      (when (and payload-bytes
                               (< from to)
                               (<= to (count payload-bytes)))
                      (java.util.Arrays/copyOfRange ^bytes payload-bytes
                                                    (int from) (int to)))}))))

(defn- split-messages [m]
  (case (:protocol m)
    :memcache (split-memcache-messages m)
    [m]))

(defn- extract-fields [m]
  (case (:protocol m)
    :dynamodb (dynamo-fields m)
    :memcache (memcache-fields m)))
(defn decode-body [{:keys [protocol body] :as m}]
  (assoc m :body
           (case protocol
             :dynamodb (decode-edn (decode-dynamo-body body))
             :memcache (some-> body fressian-decode/decode-body))))
(defn parse-datomic-traffic
  "Turns raw tshark records (as produced by parse-tshark) into decoded
   datomic-traffic events: extracts each one's typed fields, then decodes its
   body. Called with no args, returns the transducer, for composing into a
   larger `comp` chain; called with a seq of records, applies it directly and
   returns the resulting (lazy) seq -- same two-arity convention as
   `clojure.core/map`/`filter`/etc."
  ([] (map (comp decode-body extract-fields)))
  ([records] (sequence (parse-datomic-traffic) records)))

(def protocol-ports
  (into #{} (map (comp parse-long :port val)) protocols))
(defn- request? [event] (contains? protocol-ports (:dstport event)))

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

(defn- parse-line
  "One tshark JSON line -> a seq of 0+ raw protocol-message records (usually
   1, but a memcache TCP segment can pack several PDUs, or the line can be
   filtered out entirely and yield none). `since` as in parse-tshark."
  [since line]
  (for [record [(charred/read-json line :key-fn keyword)]
        :when (not (:index record))                              ; drop EK bulk-index lines
        :let [record (update record :timestamp ->long)]
        :when (or (nil? since) (>= (:timestamp record) since))
        :when (not= "0" (get-in record [:layers :tcp :tcp_tcp_len])) ; drop Syn/Ack/Fin
        :let [record (assoc record :protocol (match-protocol record))]
        :when (:protocol record)
        :let [record (-> record decode-byte-strings add-payload)]
        message (split-messages record)]
    message))

(defn parse-tshark
  "Turns tshark's JSON-per-line output into raw protocol-message records.
   `since` (epoch millis, or nil for no cutoff) drops records earlier than it
   before any of the heavier protocol-matching/byte-decoding steps run, so a
   log spanning several sessions doesn't pay to process the ones the caller
   doesn't want.

   Called with just `since`, returns the transducer, for composing into a
   larger `comp` chain; called with `since` and a seq of lines (e.g.
   `(line-seq rdr)`), applies it directly and returns the resulting (lazy)
   seq -- same two-arity convention as `clojure.core/map`/`filter`/etc."
  ([since] (mapcat (partial parse-line since)))
  ([since lines] (sequence (parse-tshark since) lines)))

; --- Putting it together: capture file -> decoded events -> SVG diagram ---

(def default-port-names {8000 :dynamodb 11211 :memcache})
(def default-protocol-styles
  {:dynamodb {:color "#FFAEFB" :label "Storage (DynamoDB)"}
   :memcache {:color "#FDFF94" :label "Cache (memcached)"}})
(defn- default-noisy?
  "Assumes the transactor's heartbeat/lease traffic is always a PutItem or
   GetItem on item id \"pod-coord\"."
  [event]
  (#{"pod-coord"} (:key event)))

(defn- read-edn-if-exists [path]
  (when (.exists (io/file path))
    (edn/read-string (slurp path))))

(defn draw-diagram!
  "Reads `tshark-log-file` (as captured by scripts/capture.sh, or setup's
   start-all!), resolves participant names from its sibling *.ports.edn,
   groups events by its sibling *.regions.edn when present, and writes an
   SVG sequence diagram. Opts:
     :svg-path        output path, default tshark-log-file + \".svg\"
     :since           epoch-millis timestamp (e.g. setup's start-all!
                      :since) -- events before it are dropped, so a log
                      spanning several sessions only diagrams the latest one
     :noisy?          predicate over a request event marking it (and its
                      paired response) noise to drop -- default drops the
                      transactor's pod-coord heartbeat; pass e.g. `(constantly
                      false)` to keep everything
     :port-names      extra port -> name entries, layered over the sibling
                      *.ports.edn (and overriding it on conflict) and the
                      dynamodb/memcache server-port defaults
     :protocol-styles merged over the default dynamodb/memcache styles
     :open?           passed through to write-svg! (default true) -- opens
                      the rendered SVG in the OS's default viewer
   Any other opt (e.g. :title, :label-fn) is passed through to
   diagram/write-svg!. Returns the SVG's absolute path."
  [tshark-log-file & [{:keys [svg-path since noisy? port-names protocol-styles]
                        :or   {svg-path (str tshark-log-file ".svg")
                               noisy?   default-noisy?}
                        :as   opts}]]
  (let [ports-path      (str tshark-log-file ".ports.edn")
        regions-path    (str tshark-log-file ".regions.edn")
        file-port-names (read-edn-if-exists ports-path)
        regions         (read-edn-if-exists regions-path)
        events          (with-open [rdr (io/reader tshark-log-file)]
                          (->> (line-seq rdr)
                               (parse-tshark since)
                               (parse-datomic-traffic)
                               (remove-noise noisy?)
                               (into [])))]
    (diagram/write-svg! events svg-path
                         (merge {:regions regions}
                                (dissoc opts :svg-path :since :noisy? :port-names :protocol-styles)
                                {:port-names      (merge default-port-names file-port-names port-names)
                                 :protocol-styles (merge default-protocol-styles protocol-styles)}))))

(comment
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
