(ns dynamodb
  "Everything specific to Datomic's DynamoDB traffic: AWS-API-shape
   extraction on top of the generic http layer, AttributeValue unwrapping,
   and Datomic's own 7-bit-packed gzip+fressian :v blob encoding. Plugs
   into protocol's multimethods and diagram's protocol-style -- nothing
   else in the pipeline knows dynamodb exists."
  (:require [clojure.edn :as edn]
            [clojure.walk :as walk]
            [fressian-decode]
            [diagram :as diagram]
            [http :as http]
            [protocol :as proto]))

(defn- dynamo-operation
  "DynamoDB's operation name, e.g. \"PutItem\" -- the part of the
   X-Amz-Target header after the service prefix (\"DynamoDB_20120810.\")."
  [headers]
  (some->> (get headers "x-amz-target")
           (re-find #"(?i)\S+\.(\S+)\s*$")
           second))

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
  [{:keys [timestamp layers] :as record}]
  (let [{:keys [tcp]} layers
        {:keys [headers status body]} (http/http-fields record)
        body (some-> body unwrap-attribute-values)]
    (proto/some-vals {:protocol       :dynamodb
                       :timestamp      (proto/->long timestamp)
                       :stream         (proto/->long (:tcp_tcp_stream tcp))
                       :srcport        (proto/->long (:tcp_tcp_srcport tcp))
                       :dstport        (proto/->long (:tcp_tcp_dstport tcp))
                       :operation      (dynamo-operation headers)
                       :key            (dynamo-key body)
                       :status         status
                       :body           body})))

; --- dynamo body decode ---

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
(defn decode-edn
  [x]
  (walk/postwalk
    (fn [v]
      (if (string? v)
        (let [parsed (try (edn/read-string v) (catch Exception _ v))]
          (if (coll? parsed) parsed v))
        v))
    x))

(def dynamo-port 8000)

(defmethod proto/protocol-matches? :dynamodb [_ record]
  (contains? (:layers record) :http))

(defmethod proto/extract-and-decode-fields :dynamodb [m]
  (let [fields (dynamo-fields m)]
    (update fields :body (comp decode-edn decode-dynamo-body))))

(defmethod proto/request? :dynamodb [e] (boolean (= dynamo-port (:dstport e))))

; Assumes the transactor's heartbeat/lease traffic is always a PutItem or
; GetItem on item id "pod-coord" -- see README's "Known item shapes".
(defmethod proto/noise? :dynamodb [e]
  (and (proto/request? e) (= "pod-coord" (:key e))))

;; Matches the Datomic architecture diagram's own palette: pink for the
;; Storage Service.
(defmethod diagram/protocol-style :dynamodb [_] {:color "#FFAEFB" :label "Storage (DynamoDB)"})
