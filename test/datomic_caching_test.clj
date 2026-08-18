(ns datomic-caching-test
  (:require [charred.api :as charred]
            [clojure.data.fressian :as fressian]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [datomic-caching :refer [attach-participants datomic-index-readers
                                      decode-datomic-known-shapes event->draw
                                      read-datomic-capture]]))

(deftest event->draw-memcache-branch
  (let [event (event->draw {:memcache {:operation :get :key "foo" :payload "bar"}})]
    (is (= "get foo" (:tag event)))
    (is (= "bar" (:note event)))
    (is (= "#FDFF94" (:color event)))))

(deftest event->draw-dynamodb-branch
  (testing "operation present: tag is \"operation key\""
    (let [event (event->draw {:dynamodb {:operation "PutItem" :key "abc" :body {:x 1}}})]
      (is (= "PutItem abc" (:tag event)))
      (is (= {:x 1} (:note event)))
      (is (= "#FFAEFB" (:color event)))))
  (testing "no operation (a response): tag falls back to the status"
    (let [event (event->draw {:dynamodb {:status 200}})]
      (is (= "200" (:tag event))))))

(deftest event->draw-http-branch
  (testing "request-method present: tag is \"METHOD uri\""
    (let [event (event->draw {:http {:request-method :get :uri "/foo" :headers {"a" "b"} :body "x"}})]
      (is (= "GET /foo" (:tag event)))
      (is (= {:headers {"a" "b"} :body "x"} (:note event)))
      (is (= "#94C9FF" (:color event)))))
  (testing "no request-method (a response): tag falls back to the status"
    (let [event (event->draw {:http {:status 404}})]
      (is (= "404" (:tag event))))))

(deftest event->draw-tcp-branch
  (let [event (event->draw {:tcp {:flags #{:SYN :ACK} :payload (byte-array (map byte "hi"))}})]
    (is (= "ACK,SYN" (:tag event)))
    (is (= "hi" (:note event)))
    (is (= "#D3D3D3" (:color event)))))

(deftest event->draw-cond-precedence-on-a-fully-stacked-event
  ;; On real input a dynamodb event is also an http event (http->dynamodb
  ;; assoc's :dynamodb onto an already-:http event) which is also a tcp
  ;; event (tshark-tcp->http assoc's :http onto an already-:tcp event) --
  ;; so :tcp/:http/:dynamodb (and separately :tcp/:memcache) are present
  ;; simultaneously, and only the cond's ordering picks dynamodb/memcache
  ;; over the more general http/tcp. Single-key fixtures can't catch a
  ;; reordering of the cond; a fully-stacked event can.
  (testing "dynamodb wins over http and tcp"
    (let [event (event->draw {:tcp      {:flags #{} :payload (byte-array 0)}
                              :http     {:status 200}
                              :dynamodb {:operation "GetItem" :key "abc" :body {}}})]
      (is (= "#FFAEFB" (:color event)))))
  (testing "memcache wins over tcp"
    (let [event (event->draw {:tcp      {:flags #{} :payload (byte-array 0)}
                              :memcache {:operation :get :key "foo" :payload "bar"}})]
      (is (= "#FDFF94" (:color event))))))

(deftest attach-participants-resolves-known-and-unknown-ports
  (let [port->name {8000 :storage 11211 :cache}
        event {:tcp {:src-port 11211 :dst-port 8000}}]
    (is (= {:from :cache :to :storage} (select-keys (attach-participants port->name event) [:from :to]))))
  (testing "a port missing from port->name falls back to :unknown-<port>"
    (let [event {:tcp {:src-port 12345 :dst-port 8000}}]
      (is (= :unknown-12345 (:from (attach-participants {8000 :storage} event))))
      (is (= :storage (:to (attach-participants {8000 :storage} event)))))))

(defn- fressian-bytes
  "Plain (non-gzipped) fressian encoding of `v`, as a byte[] -- decode-body
   only gunzips when the magic bytes are present, so this exercises its
   plain-fressian path."
  ^bytes [v]
  (let [buf (fressian/write v)
        arr (byte-array (.remaining buf))]
    (.get buf arr)
    arr))

(defn- pack-7bit-lsb
  "Inverse of utils/unpack-7bit-lsb, for building test fixtures: repacks
   `bytes` (byte count must be a multiple of 7, so no trailing bits are lost)
   into a string of 7-bit codepoints, LSB-first, matching the on-the-wire
   encoding Datomic/DynamoDB actually use."
  [^bytes bytes]
  (let [bits (for [byte-idx (range (alength bytes))
                    bit-idx (range 8)]
               (bit-test (aget bytes byte-idx) bit-idx))]
    (->> (partition 7 bits)
         (map (fn [chunk]
                (char (reduce-kv (fn [acc b bit?] (if bit? (bit-or acc (bit-shift-left 1 b)) acc))
                                 0 (vec chunk)))))
         (apply str))))

(deftest decode-datomic-known-shapes-memcache-payload
  (testing "a non-empty memcache payload is fressian-decoded in place"
    (let [event {:memcache {:payload (fressian-bytes "hello")}}]
      (is (= "hello" (:payload (:memcache (decode-datomic-known-shapes event)))))))
  (testing "an empty/nil payload doesn't match this branch -- falls through to :else"
    (let [event {:memcache {:payload nil}}]
      (is (= event (decode-datomic-known-shapes event))))))

(deftest decode-datomic-known-shapes-pod-heartbeat-key
  (testing "a pod-standby/pod-coord id edn-decodes the Item's :key"
    (let [event {:dynamodb {:body {:Item {:id  {:S "pod-coord"}
                                          :key {:S "[\"127.0.0.1\" 1 2]"}}}}}
          out   (decode-datomic-known-shapes event)]
      (is (= ["127.0.0.1" 1 2] (get-in out [:dynamodb :body :Item :key :S])))))
  (testing "no :key on the Item is a no-op, not a thrown exception or a
            grafted-in nil -- see utils/update-in-if-present"
    (let [event {:dynamodb {:body {:Item {:id {:S "pod-coord"}}}}}]
      (is (= event (decode-datomic-known-shapes event))))))

(deftest decode-datomic-known-shapes-uuid-value
  (testing "a UUID-keyed row's :v is 7-bit-unpacked then fressian-decoded"
    (let [payload (fressian-bytes :hello)
          padded  (byte-array (concat payload (repeat (- 7 (mod (count payload) 7)) 0)))
          event   {:dynamodb {:body {:Item {:id {:S (str (random-uuid))}
                                            :v  {:S (pack-7bit-lsb padded)}}}}}
          out     (decode-datomic-known-shapes event)]
      (is (= :hello (get-in out [:dynamodb :body :Item :v :S]))))))

(deftest decode-datomic-known-shapes-else-passthrough
  (testing "an event matching none of the three shapes is returned untouched"
    (let [event {:http {:status 200}}]
      (is (= event (decode-datomic-known-shapes event))))))

(deftest datomic-index-readers-index-tdata-zips-parallel-columns-into-rows
  (let [reader (get datomic-index-readers "index-tdata")
        v [100 200] e [1 2] a [10 20] t [1000 2000] added [true false]
        result (reader "index-tdata" [v e a t added])]
    (is (= "index-tdata" (name (:tag result))))
    (is (= [{:e 1 :a 10 :v 100 :t 1000 :added true}
            {:e 2 :a 20 :v 200 :t 2000 :added false}]
           (:form result)))))

(defn- hex-encode [^bytes bytes]
  (str/join ":" (map #(format "%02x" (bit-and % 0xff)) bytes)))

(defn- dynamodb-record
  "One synthetic tshark record for a DynamoDB PutItem-shaped JSON body,
   on stream `stream` -- same wire shape read-datomic-capture actually
   consumes (raw :layers, hex-encoded :http_http_file_data), not the
   already-decoded event shapes the other tests build by hand."
  [stream item]
  {:timestamp "1"
   :layers    {:tcp  {:tcp_tcp_srcport "54321" :tcp_tcp_dstport "8000"
                      :tcp_tcp_payload "" :tcp_tcp_len "0" :tcp_tcp_stream (str stream)}
               :http {:http_http_request_method "POST"
                      :http_http_request_uri    "/"
                      :http_http_request_line   ["Content-Type: application/json"]
                      :http_http_file_data      (hex-encode (.getBytes ^String (charred/write-json-str {:Item item})
                                                                       "UTF-8"))}}})

(deftest read-datomic-capture-end-to-end-smoke-test
  (testing "the pod-coord heartbeat is dropped as noise, and the other record survives
            with its UUID-keyed :v decoded -- proving both halves of the pipeline,
            not just that the (vacuously passable) result happens to be empty"
    (let [noisy    (dynamodb-record 1 {:id {:S "pod-coord"} :key {:S "\"x\""}})
          payload  (fressian-bytes :hello)
          padded   (byte-array (concat payload (repeat (- 7 (mod (count payload) 7)) 0)))
          uuid     (str (random-uuid))
          keeper   (dynamodb-record 2 {:id {:S uuid} :v {:S (pack-7bit-lsb padded)}})
          contents (str/join "\n" (map charred/write-json-str [noisy keeper]))
          [event]  (read-datomic-capture contents :port->protocol {8000 :dynamodb})]
      (is (= uuid (get-in event [:dynamodb :body :Item :id :S])))
      (is (= :hello (get-in event [:dynamodb :body :Item :v :S]))))))
