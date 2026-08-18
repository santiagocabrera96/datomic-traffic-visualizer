(ns memcache
  (:require [tshark :refer [decode-protocol]]
            [utils :refer [->vec]])
  (:import (java.util Arrays)))

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
        :memcache {:operation operation
                   :key       k
                   :status    status
                   :payload   payload}))))

(defmethod decode-protocol :memcache [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :memcache :layers))
       (mapcat tshark-tcp->memcache)))
