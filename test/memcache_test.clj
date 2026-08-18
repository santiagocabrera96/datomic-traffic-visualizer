(ns memcache-test
  (:require [clojure.test :refer [deftest is testing]]
            [memcache :refer [opcode->command status->outcome tshark-tcp->memcache]]))

(defn- bytes->str [b]
  (String. ^bytes b "UTF-8"))

(defn- pdu
  "A memcache_memcache_* field map plus its raw 24-byte-header+extras+key+value
   bytes, for one PDU -- extras are zero-filled, header bytes are irrelevant
   junk since tshark-tcp->memcache only reads the parsed fields, never the
   header bytes themselves."
  [{:keys [opcode status key value extras-len]
    :or   {extras-len 0}}]
  (let [key-bytes   (.getBytes ^String key "UTF-8")
        value-bytes (.getBytes ^String value "UTF-8")
        total       (+ extras-len (count key-bytes) (count value-bytes))
        bytes       (byte-array (concat (repeat (+ 24 extras-len) (byte 0))
                                         key-bytes
                                         value-bytes))]
    {:fields {:memcache_memcache_opcode             (str opcode)
              :memcache_memcache_status             (str status)
              :memcache_memcache_key                key
              :memcache_memcache_total_body_length  (str total)
              :memcache_memcache_extras_length      (str extras-len)
              :memcache_memcache_key_length         (str (count key-bytes))}
     :bytes  bytes}))

(defn- tcp-event [& pdus]
  (let [built (map pdu pdus)]
    {:layers {:memcache (mapv :fields built)}
     :tcp    {:payload (byte-array (mapcat (comp seq :bytes) built))}}))

(deftest single-pdu-decodes-end-to-end
  (let [event (tcp-event {:opcode 0x00 :status 0x00 :key "foo" :value "bar"})
        [out] (tshark-tcp->memcache event)]
    (is (= :get (:operation (:memcache out))))
    (is (= :ok (:status (:memcache out))))
    (is (= "foo" (:key (:memcache out))))
    (is (= "bar" (bytes->str (:payload (:memcache out)))))))

(deftest two-pdus-in-one-payload-decode-independently
  (let [event (tcp-event {:opcode 0x00 :status 0x00 :key "foo" :value "bar"}
                          {:opcode 0x01 :status 0x01 :key "baz" :value "quux"})
        [first-out second-out] (tshark-tcp->memcache event)]
    (testing "first PDU"
      (is (= :get (:operation (:memcache first-out))))
      (is (= "foo" (:key (:memcache first-out))))
      (is (= "bar" (bytes->str (:payload (:memcache first-out))))))
    (testing "second PDU, at a non-zero byte offset into the shared payload"
      (is (= :set (:operation (:memcache second-out))))
      (is (= :not-found (:status (:memcache second-out))))
      (is (= "baz" (:key (:memcache second-out))))
      (is (= "quux" (bytes->str (:payload (:memcache second-out))))))))

(deftest opcode->command-maps-a-representative-entry
  (is (= :get (opcode->command 0x00)))
  (is (= :set (opcode->command 0x01))))

(deftest status->outcome-maps-a-representative-entry
  (is (= :ok (status->outcome 0x00)))
  (is (= :not-found (status->outcome 0x01))))
