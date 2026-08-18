(ns http
  "Decodes tshark's :http layer into a plain event map and self-registers
   a :http decode-protocol method -- requires tshark (rather than tshark
   requiring this) so adding a protocol only means requiring its namespace
   somewhere, never editing tshark.clj."
  (:require [charred.api :as charred]
            [clojure.string :as str]
            [tshark :refer [decode-protocol]]
            [utils :refer [->vec hex-payload->bytes some-vals]]))

(defn- json-body
  "bytes decoded as JSON -- nil if empty, or it doesn't parse as JSON.
   Swallows parse failures rather than throwing: a non-JSON/truncated body
   on a JSON-labelled request is just something to skip over, not a reason
   to abort decoding the whole capture."
  [^bytes body-bytes]
  (when (and body-bytes (pos? (alength body-bytes)))
    (try (charred/read-json (String. body-bytes "UTF-8") :key-fn keyword)
         (catch Exception _ nil))))

(defn- parse-headers [lines]
  (into {}
        (keep (fn [line]
                (when-let [[_ k v] (re-matches #"(?s)([^:]+):\s*(.*)" (str line))]
                  ;; lowercased so callers can look up "Content-Type" and
                  ;; "content-type" the same way regardless of what casing
                  ;; the client/server on the wire happened to use.
                  [(str/lower-case (str/trim k)) (str/trim v)])))
        (->vec lines)))

(defn- json-content-type? [headers]
  (boolean (some->> (get headers "content-type") (re-find #"(?i)json"))))

(defn tshark-tcp->http
  "A tcp-layer event with tshark's parsed :http fields as {:request-method
   :uri :headers :status :body}, merged into the event under :http. Keys
   that don't apply (e.g. :status on a request, :request-method/:uri on a
   response) are dropped rather than nil -- see some-vals."
  [tcp-event]
  (let [{{http :http} :layers} tcp-event]
    (let [request-method (some-> (:http_http_request_method http) str/lower-case keyword)
          uri            (:http_http_request_uri http)
          headers        (parse-headers (or (:http_http_request_line http)
                                            (:http_http_response_line http)))
          status         (some-> (:http_http_response_code http) parse-long)
          body-bytes     (byte-array (hex-payload->bytes (:http_http_file_data http)))
          body           (when (json-content-type? headers) (json-body body-bytes))]
      (assoc tcp-event
        :http (some-vals
                {:request-method request-method
                 :uri            uri
                 :headers        headers
                 :status         status
                 :body           body})))))

(defmethod decode-protocol :http [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :http :layers))
       (map tshark-tcp->http)))

(comment
  ;; A JSON request: method/uri/headers/body all present, body parsed
  ;; because content-type says json.
  (tshark-tcp->http
    {:layers {:http {:http_http_request_method "POST"
                      :http_http_request_uri    "/api/v1"
                      :http_http_request_line   ["Content-Type: application/json"
                                                  "Content-Length: 12"]
                      :http_http_file_data      "7b:22:6f:6b:22:3a:74:72:75:65:7d"}}})

  ;; A plain-text response: no :request-method/:uri (they weren't on the
  ;; wire), :status present, :body absent -- content-type isn't json so
  ;; json-body is never called and the nil body gets dropped by some-vals.
  (tshark-tcp->http
    {:layers {:http {:http_http_response_line ["Content-Type: text/plain"]
                      :http_http_response_code "200"
                      :http_http_file_data     "68:65:6c:6c:6f:20:77:6f:72:6c:64"}}})

  ;; No request/response line at all -- :headers ends up {} (parse-headers
  ;; of nil), and since there's no method/uri/status/body either, some-vals
  ;; drops everything: :http comes back as an event with only :headers {}.
  (tshark-tcp->http {:layers {:http {}}}))
