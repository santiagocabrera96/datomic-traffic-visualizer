(ns http-test
  (:require [clojure.test :refer [deftest is testing]]
            [http :refer [tshark-tcp->http]]))

(defn- ->tcp-event [http-layer]
  {:layers {:http http-layer}})

(deftest full-request-test
  (testing "method/uri/headers/body all present on a JSON request"
    (let [event (->tcp-event
                  {:http_http_request_method "POST"
                   :http_http_request_uri    "/api/v1"
                   :http_http_request_line   ["Content-Type: application/json"
                                               "Content-Length: 12"]
                   :http_http_file_data      "7b:22:6f:6b:22:3a:74:72:75:65:7d"})]
      (is (= {:request-method :post
              :uri            "/api/v1"
              :headers        {"content-type"   "application/json"
                                "content-length" "12"}
              :body           {:ok true}}
             (:http (tshark-tcp->http event)))))))

(deftest response-test
  (testing "a response has :status but no :request-method/:uri"
    (let [event (->tcp-event
                  {:http_http_response_line ["Content-Type: text/plain"]
                   :http_http_response_code "200"
                   :http_http_file_data     "68:65:6c:6c:6f:20:77:6f:72:6c:64"})
          http  (:http (tshark-tcp->http event))]
      (is (= 200 (:status http)))
      (is (not (contains? http :request-method)))
      (is (not (contains? http :uri))))))

(deftest json-body-parsed-only-with-json-content-type-test
  (testing "json content-type -> parsed map"
    (let [event (->tcp-event
                  {:http_http_response_line ["Content-Type: application/json"]
                   :http_http_file_data     "7b:22:6f:6b:22:3a:74:72:75:65:7d"})]
      (is (= {:ok true} (:body (:http (tshark-tcp->http event)))))))
  (testing "non-json content-type -> body left unparsed (absent)"
    (let [event (->tcp-event
                  {:http_http_response_line ["Content-Type: text/plain"]
                   :http_http_file_data     "7b:22:6f:6b:22:3a:74:72:75:65:7d"})]
      (is (not (contains? (:http (tshark-tcp->http event)) :body))))))

(deftest malformed-json-body-does-not-throw-test
  (testing "json content-type but unparseable body -> :body dropped, no exception"
    (let [event (->tcp-event
                  {:http_http_response_line ["Content-Type: application/json"]
                   :http_http_file_data     "6e:6f:74:20:6a:73:6f:6e"})] ; "not json"
      (is (not (contains? (:http (tshark-tcp->http event)) :body))))))

(deftest header-parsing-is-case-insensitive-test
  (testing "Content-Type vs content-type both resolve via the lowercased key"
    (let [event (->tcp-event
                  {:http_http_request_line ["Content-Type: application/json"]})]
      (is (= "application/json" (get (:headers (:http (tshark-tcp->http event))) "content-type"))))))

(deftest no-request-or-response-line-test
  (testing "nil-valued keys (method/uri/status/body) are genuinely dropped"
    (let [event (->tcp-event {})
          http  (:http (tshark-tcp->http event))]
      (is (= {:headers {}} http))
      (is (not (contains? http :request-method)))
      (is (not (contains? http :uri)))
      (is (not (contains? http :status)))
      (is (not (contains? http :body))))))
