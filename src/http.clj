(ns http
  "Generic HTTP layer, riding on tshark's own HTTP dissection: parses
   header lines into a {name -> value} map (names lowercased), and decodes
   the body according to Content-Type. Knows nothing about any specific
   API built on top of HTTP -- protocols that ride on HTTP (e.g. dynamodb)
   compose this instead of re-parsing headers/body themselves.

   Also self-registers as a plain, standalone :http protocol (see the
   protocol-matches?/extract-and-decode-fields methods at the bottom) --
   pass {port :http} instead of {port :dynamodb} in read-messages'/
   draw-diagram!'s ports map to diagram that port's traffic as raw HTTP,
   which is a handy way to eyeball that this namespace's own decoding is
   right, independent of any protocol built on top of it."
  (:require [charred.api :as charred]
            [clojure.string :as str]
            [diagram :as diagram]
            [protocol :as proto]))

(defn- parse-header-line
  "One tshark http.request.line entry (\"Name: value\") into
   [lowercased-name value], or nil if it doesn't look like a header line."
  [line]
  (let [line (str line)
        idx  (.indexOf line ":")]
    (when (pos? idx)
      [(-> (subs line 0 idx) str/trim str/lower-case)
       (-> (subs line (inc idx)) str/trim)])))

(defn headers
  "{lowercased-header-name -> value}, parsed from tshark's
   http.request.line -- a vector of raw header lines for headers tshark
   doesn't otherwise break out into their own named fields (e.g.
   X-Amz-Target)."
  [http-layer]
  (into {} (keep parse-header-line) (proto/->vec (:http_http_request_line http-layer))))

(defn- normalize-content-type
  "Strips parameters (e.g. \"; charset=utf-8\") and case, so parse-body
   dispatch doesn't need to know every way a content-type can be written."
  [content-type]
  (some-> content-type (str/split #";") first str/trim str/lower-case))

(defmulti parse-body
  "Decode `body-bytes` per `content-type`. Dispatches on the normalized
   content-type; :default passes the bytes through undecoded. New body
   shapes (xml, protobuf, ...) plug in with another defmethod here,
   without any protocol built on http needing to know about it."
  (fn [content-type _body-bytes] (normalize-content-type content-type)))

(defmethod parse-body :default [_ body-bytes] body-bytes)

(defn- parse-json-bytes [^bytes body-bytes]
  (when (and body-bytes (pos? (alength body-bytes)))
    (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
         (catch Exception _ nil))))

(defmethod parse-body "application/json" [_ body-bytes] (parse-json-bytes body-bytes))
;; DynamoDB's (and other AWS JSON-protocol services') wire content-type.
(defmethod parse-body "application/x-amz-json-1.0" [_ body-bytes] (parse-json-bytes body-bytes))
(defmethod parse-body "application/x-amz-json-1.1" [_ body-bytes] (parse-json-bytes body-bytes))

(defn http-fields
  "The generic part of a decoded HTTP exchange: parsed headers, response
   status (nil on requests), and the body decoded per Content-Type.
   Protocol-specific decoders (e.g. dynamodb's dynamo-fields) start from
   this instead of reading tshark's :http layer directly."
  [{:keys [layers]}]
  (let [http (:http layers)
        hs   (headers http)
        ct   (or (:http_http_content_type http) (get hs "content-type"))]
    {:headers hs
     :status  (proto/->long (:http_http_response_code http))
     :body    (parse-body ct (:http_http_file_data http))}))

;; --- standalone :http protocol, for diagramming/validating this
;;     namespace's own decoding directly (see the ns docstring) ---

(defn- request-summary
  "\"METHOD /uri\" for a request record, or nil for a response (tshark
   only dissects http.request.method/uri on the request side)."
  [http-layer]
  (when-let [method (:http_http_request_method http-layer)]
    (str method " " (:http_http_request_uri http-layer))))

(defn http-event-fields
  "diagram's note-lines only ever renders :body, so headers are folded into
   it here (rather than kept as a sibling :headers field) -- otherwise
   they'd silently never show up in the diagram."
  [{:keys [timestamp layers]}]
  (let [{:keys [tcp http]} layers
        {:keys [headers status body]} (http-fields {:layers layers})]
    (proto/some-vals {:protocol  :http
                       :timestamp (proto/->long timestamp)
                       :stream    (proto/->long (:tcp_tcp_stream tcp))
                       :srcport   (proto/->long (:tcp_tcp_srcport tcp))
                       :dstport   (proto/->long (:tcp_tcp_dstport tcp))
                       :operation (or (request-summary http) (some->> status (str "HTTP ")))
                       :status    status
                       :body      (proto/some-vals {:headers headers :body body})})))

(defmethod proto/protocol-matches? :http [_ record]
  (contains? (:layers record) :http))

(defmethod proto/extract-and-decode-fields :http [m]
  (http-event-fields m))

(defmethod diagram/protocol-style :http [_] {:color "#CCCCCC" :label "HTTP"})
