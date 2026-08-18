(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [tshark :refer [decode-protocol read-tshark remove-noise]]))

(defn- tshark-line
  "One tshark -T json record as a JSON string, with the minimal :tcp layer
   fields read-tshark/tshark->tcp actually look at."
  [{:keys [timestamp src-port dst-port stream len payload]
    :or   {payload "" len 0}}]
  (charred/write-json-str
    {:timestamp (str timestamp)
     :layers    {:tcp {:tcp_tcp_srcport (str src-port)
                       :tcp_tcp_dstport (str dst-port)
                       :tcp_tcp_stream  (str stream)
                       :tcp_tcp_len     (str len)
                       :tcp_tcp_payload payload}}}))

(defn- log [& records] (str/join "\n" (map tshark-line records)))

(deftest read-tshark-parses-minimal-record
  (let [[event] (read-tshark (log {:timestamp 100 :src-port 8000 :dst-port 54321 :stream 1}))]
    (testing ":server-port is the min of src/dst port"
      (is (= 8000 (:server-port event))))
    (testing ":timestamp is parsed to a long"
      (is (= 100 (:timestamp event))))
    (testing "the :tcp layer is parsed into :src-port/:dst-port/:stream"
      (is (= 8000 (:src-port (:tcp event))))
      (is (= 54321 (:dst-port (:tcp event))))
      (is (= 1 (:stream (:tcp event)))))))

(deftest read-tshark-filters-by-since-and-until
  (let [contents (log {:timestamp 100 :src-port 1 :dst-port 2 :stream 1}
                       {:timestamp 200 :src-port 1 :dst-port 2 :stream 1}
                       {:timestamp 300 :src-port 1 :dst-port 2 :stream 1})]
    (is (= [100 200 300] (map :timestamp (read-tshark contents))))
    (is (= [200 300] (map :timestamp (read-tshark contents :since 200))))
    (is (= [100 200] (map :timestamp (read-tshark contents :until 200))))
    (is (= [200] (map :timestamp (read-tshark contents :since 200 :until 200))))))

(defn- decoded->comparable
  "Strips the raw byte-array payload (never `=` to an equal-but-distinct
   array) so two decode-protocol results can be compared by value."
  [decoded]
  (mapv #(update % :tcp dissoc :payload) decoded))

(deftest decode-protocol-falls-back-to-tcp-for-unknown-protocols
  (let [record {:layers {:tcp {:tcp_tcp_srcport "1" :tcp_tcp_dstport "2"
                               :tcp_tcp_stream "1" :tcp_tcp_len "0" :tcp_tcp_payload ""}}}]
    (is (= (decoded->comparable (decode-protocol :tcp record))
           (decoded->comparable (decode-protocol :some-unregistered-protocol record))))))

(defn- request [server-port stream]
  {:server-port server-port :tcp {:dst-port server-port :stream stream}})

(defn- response [server-port stream]
  {:server-port server-port :tcp {:dst-port 55555 :stream stream}})

(deftest remove-noise-drops-a-request-and-its-paired-response
  (let [noisy-req  (request 8000 1)
        noisy-resp (response 8000 1)
        quiet-req  (request 8000 1)
        quiet-resp (response 8000 1)
        events     [noisy-req noisy-resp quiet-req quiet-resp]
        out        (remove-noise (constantly true) [noisy-req noisy-resp])
        kept       (remove-noise #(identical? % noisy-req) events)]
    (is (empty? out))
    (is (= [quiet-req quiet-resp] kept))))

(deftest remove-noise-pairs-per-stream-and-leaves-other-streams-untouched
  ;; This is exactly the scenario a regression to keying the pending queue
  ;; off a top-level :stream (instead of (:stream (:tcp e))) would break:
  ;; two streams' events are interleaved, and only :tcp :stream exists here
  ;; -- there is no top-level :stream on any event.
  (let [noisy-req    (request 8000 1)
        noisy-resp   (response 8000 1)
        other-req    (request 8000 2)
        other-resp   (response 8000 2)
        events       [noisy-req other-req noisy-resp other-resp]
        noisy?       #(identical? % noisy-req)
        kept         (remove-noise noisy? events)]
    (is (= [other-req other-resp] kept))))

(deftest remove-noise-two-arity-matches-transducer-arity
  (let [events [(request 8000 1) (response 8000 1)]]
    (is (= (remove-noise (constantly false) events)
           (into [] (remove-noise (constantly false)) events)))))
