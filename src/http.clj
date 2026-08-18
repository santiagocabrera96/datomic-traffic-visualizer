(ns http
  (:require [charred.api :as charred]
            [clojure.string :as str]
            [utils :refer [->vec hex-payload->bytes some-vals]]))

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

