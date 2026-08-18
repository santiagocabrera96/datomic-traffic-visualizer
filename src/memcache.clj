(ns memcache
  "Decodes memcache PDUs out of tshark TCP events -- see tshark-tcp->memcache.
   Requires tshark (rather than the other way around) so that requiring this
   namespace is what registers :memcache as a decode-protocol/read-tshark
   :port->protocol value; tshark.clj itself knows nothing about memcache."
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

(defn tshark-tcp->memcache
  "One event per memcache PDU found in `tcp-event`'s :tcp :payload (a TCP
   segment can coalesce several PDUs back-to-back, hence 1->many). tshark
   parses each PDU's header fields into :layers :memcache but leaves the
   payload as one undifferentiated byte blob for the whole segment, so the
   value bytes for each PDU have to be sliced out by hand: `total_body_length`
   is tshark's name for extras+key+value length (i.e. everything after the
   fixed 24-byte header), and `reductions +` over each PDU's total on-wire
   length (header included) gives the byte offset each PDU starts at within
   the shared payload."
  [tcp-event]
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

(comment
  ;; A single memcache GET response PDU: opcode 0x00/status 0x00, key "foo",
  ;; no extras, value "bar" -- total_body_length is key+value = 6, so the PDU
  ;; is 24 (header) + 6 = 30 bytes on the wire. The header bytes themselves
  ;; are never read by tshark-tcp->memcache (only the parsed
  ;; memcache_memcache_* fields are), so they're left as zeros here.
  (def get-response
    {:layers {:memcache [{:memcache_memcache_opcode            "0"
                          :memcache_memcache_status            "0"
                          :memcache_memcache_key               "foo"
                          :memcache_memcache_extras_length     "0"
                          :memcache_memcache_key_length        "3"
                          :memcache_memcache_total_body_length "6"}]}
     :tcp    {:payload (byte-array (concat (repeat 24 (byte 0))
                                            (map byte "foo")
                                            (map byte "bar")))}})
  (tshark-tcp->memcache get-response)
  ;;=> ({..., :memcache {:operation :get, :key "foo", :status :ok,
  ;;                     :payload #object[byte[] ...]}})
  (String. ^bytes (:payload (:memcache (first (tshark-tcp->memcache get-response)))))
  ;;=> "bar"

  ;; decode-protocol :memcache is what read-tshark dispatches to once this ns
  ;; is required (see tshark.clj's comment block). Unlike tshark-tcp->memcache
  ;; above, it takes a *raw* tshark record (:layers :tcp with a hex payload
  ;; string, not yet the shaped :tcp event) -- it decodes :tcp itself, filters
  ;; down to records tshark actually parsed a memcache layer for, then expands
  ;; each into its 1+ PDU events.
  (require '[clojure.string :as str])
  (def raw-record
    {:layers {:tcp      {:tcp_tcp_srcport "11211"
                         :tcp_tcp_dstport "54321"
                         :tcp_tcp_payload (str/join ":" (map #(format "%02x" (bit-and % 0xff))
                                                             (:payload (:tcp get-response))))
                         :tcp_tcp_len     "30"
                         :tcp_tcp_stream  "0"}
              :memcache (:memcache (:layers get-response))}})
  (decode-protocol :memcache raw-record)

  opcode->command
  status->outcome)
