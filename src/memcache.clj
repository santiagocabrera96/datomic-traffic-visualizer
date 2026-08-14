(ns memcache
  "Everything specific to the memcache binary protocol: PDU splitting,
   opcode/status lookup tables, and key/body field extraction. Plugs into
   protocol's multimethods and diagram's protocol-style -- nothing
   else in the pipeline knows memcache exists."
  (:require [fressian-decode]
            [diagram :as diagram]
            [protocol :as proto]))

(defn split-memcache-messages
  "One tshark packet record, possibly carrying several memcache PDUs packed
   into a single TCP segment, split into one record per PDU. Each result
   looks like an independent single-PDU packet: :layers :memcache is that
   PDU's map (never a vector), and :tcp_payload is narrowed to just that
   PDU's own bytes (24-byte header + its total_body_length), not the whole
   segment."
  [{:keys [layers] :as record}]
  (let [{:keys [tcp memcache]} layers
        ms      (proto/->vec memcache)
        payload (:tcp_payload tcp)]
    (if (<= (count ms) 1)
      [record]
      (first
        (reduce (fn [[acc offset] m]
                  (let [pdu-len   (+ 24 (proto/->long (:memcache_memcache_total_body_length m)))
                        pdu-bytes (java.util.Arrays/copyOfRange payload offset (+ offset pdu-len))]
                    [(conj acc (-> record
                                   (assoc-in [:layers :memcache] m)
                                   (assoc-in [:layers :tcp :tcp_payload] pdu-bytes)))
                     (+ offset pdu-len)]))
                [[] 0]
                ms)))))

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
(defn memcache-fields
  "The subset of one raw tshark memcache packet record that memcache needs.
   :memcache_memcache_key/:memcache_memcache_status only show up on some
   opcodes -- absent otherwise, which is fine, they're optional here."
  [{:keys [timestamp layers]}]
  (let [{:keys [tcp memcache]} layers]
    (let [payload-bytes (:tcp_payload tcp)
          total (proto/->long (:memcache_memcache_total_body_length memcache))
          extras (proto/->long (:memcache_memcache_extras_length memcache))
          key-len (proto/->long (:memcache_memcache_key_length memcache))
          from (+ 24 extras key-len)
          to (+ 24 total)]
      (proto/some-vals
        {:protocol  :memcache
         :timestamp (proto/->long timestamp)
         :stream    (proto/->long (:tcp_tcp_stream tcp))
         :srcport   (proto/->long (:tcp_tcp_srcport tcp))
         :dstport   (proto/->long (:tcp_tcp_dstport tcp))
         :operation (opcode->command (proto/->long (:memcache_memcache_opcode memcache)) :unknown)
         :status    (status->outcome (proto/->long (:memcache_memcache_status memcache)))
         :opaque    (proto/->long (:memcache_memcache_opaque memcache))
         :key       (:memcache_memcache_key memcache)
         :body      (when (and payload-bytes
                               (< from to)
                               (<= to (count payload-bytes)))
                      (java.util.Arrays/copyOfRange ^bytes payload-bytes
                                                    (int from) (int to)))}))))

(defmethod proto/split-protocol-messages :memcache [m] (split-memcache-messages m))

(defmethod proto/protocol-matches? :memcache [_ record]
  (contains? (:layers record) :memcache))

;; memcache's binary protocol echoes a client-chosen opaque value back on
;; the matching response -- a real wire-level correlation token, so
;; remove-noise doesn't need to fall back to assuming in-order responses.
(defmethod proto/correlation-id :memcache [e] (:opaque e))

(defmethod proto/extract-and-decode-fields :memcache [m]
  (let [fields (memcache-fields m)]
    (update fields :body #(some-> % fressian-decode/decode-body))))

;; Matches the Datomic architecture diagram's own palette: yellow for the
;; peer's Cache.
(defmethod diagram/protocol-style :memcache [_] {:color "#FDFF94" :label "Cache (memcached)"})
