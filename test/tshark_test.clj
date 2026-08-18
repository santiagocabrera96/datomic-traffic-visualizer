(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [fressian-decode]
            [tshark :refer [decode-protocol read-tshark remove-noise]]
            [memcache :refer [tshark-tcp->memcache]]
            [http :refer [tshark-tcp->http]]
            [dynamodb :refer [http->dynamodb]]
            [utils :refer [some-vals hex-payload->bytes update-in-if-present unpack-7bit-lsb ->vec]]))


(defmethod decode-protocol :memcache [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :memcache :layers))
       (mapcat tshark-tcp->memcache)))

(defmethod decode-protocol :http [_ record]
  (->> (decode-protocol :tcp record)
       (filter (comp :http :layers))
       (map tshark-tcp->http)))

(defmethod decode-protocol :dynamodb [_ record]
  (map http->dynamodb (decode-protocol :http record)))

(defmulti draw
  "Given an event (:tcp/:memcache/:http/:dynamo) is already parsed and merged in, decides
   what diagram.clj should draw for it, returning `event` with :tag/:note/:color
   added. Dispatches on :type."
  :type)

(defmethod draw :tcp [event]
  (let [{:keys [flags payload]} (:tcp event)]
    (assoc event
      :tag (str/join "," (map name (filter flags [:URG :ACK :PSH :RST :SYN :FIN])))
      :note (String. payload)
      :color "#D3D3D3")))

(defmethod draw :memcache [event]
  (let [{:keys [key operation payload]} (:memcache event)]
    (when key (def event event))
    (assoc event
      :tag (str (name operation) " " key)
      :note payload
      :color "#FDFF94")))

(defmethod draw :http [event]
  (let [{:keys [request-method uri status headers body]} (:http event)]
    (assoc event
      :tag  (or (some-> request-method name str/upper-case (str " " uri)) (str status))
      :note {:headers headers
             :body body}
      :color "#94C9FF")))

(defmethod draw :dynamodb [event]
  (let [{:keys [operation key body status]} (:dynamodb event)]
    (assoc event
      :tag  (if operation (str operation " " key) (str status))
      :note body
      :color "#FFAEFB")))

(defn attach-participants
  "Adds :from/:to to each event, naming its :tcp src-port/dst-port via
   `port->name` -- a port missing from it becomes :unknown-<port>."
  [port->name event]
  (let [{:keys [src-port dst-port]} (:tcp event)]
    (assoc event
      :from (port->name src-port (keyword (str "unknown-" src-port)))
      :to   (port->name dst-port (keyword (str "unknown-" dst-port))))))

; TODO: Remove multi-method fressian-decode/decode-tagged. Instead pass readers map as a parameter. Equivalent to the multi-method approaach, if the literal is not found do. (tagged-literal (symbol tag) form)
(defn decode-datomic [event]
  (cond
    (seq (:payload (:memcache event)))
    (update-in event [:memcache :payload] fressian-decode/decode-body)

    (#{"pod-standby" "pod-coord"} (:S (:id (:Item (:body (:dynamodb event))))))
    (update-in-if-present event [:dynamodb :body :Item :key :S] edn/read-string)

    (some-> (:S (:id (:Item (:body (:dynamodb event))))) parse-uuid)
    (update-in-if-present event [:dynamodb :body :Item :v :S] (comp fressian-decode/decode-body unpack-7bit-lsb))

    :else event))

(comment
  (require '[diagram])

  (read-tshark (->> [{:timestamp "1"
                      :layers    {:tcp {:tcp_tcp_srcport "123"
                                        :tcp_tcp_dstport "12"
                                        :tcp_tcp_payload "00:01"
                                        :tcp_tcp_len "2"
                                        :tcp_tcp_stream "1"}}}]
                    (map charred/write-json-str)
                    (str/join "\n")))
  (defmethod decode-protocol :pepe [_ record]
    [{:hello :world}])
  (read-tshark (->> [{:timestamp "1"
                      :layers    {:tcp {:tcp_tcp_srcport "123"
                                        :tcp_tcp_dstport "12"
                                        :tcp_tcp_payload "00:01"
                                        :tcp_tcp_len "2"
                                        :tcp_tcp_stream "1"}}}]
                    (map charred/write-json-str)
                    (str/join "\n"))
               :port->protocol {12 :pepe})
  (remove-method decode-protocol :pepe)

  (def tshark-records (read-tshark "/tmp/tshark.log"
                                   :port->protocol {8000  :dynamodb
                                                    11211 :memcache}))
  (def events
    (->> tshark-records
         (remove-noise (comp #{"pod-coord"} :key :dynamodb))
         (map decode-datomic)))
  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (def regions (clojure.edn/read-string (slurp "/tmp/tshark.log.regions.edn")))
  (def legend
    [{:color "#FFAEFB" :label "Storage (DynamoDB)"}
     {:color "#FDFF94" :label "Cache (memcached)"}
     {:color "#D3D3D3" :label "TCP"}
     {:color "#94C9FF" :label "HTTP"}])

  ; Regions, needed and orthogonal, is naming sections of the diagram by timestamp.
  ; port->name, optional, not needed.
  (diagram/write-svg! (map (comp draw (partial attach-participants port-names)) events) "/tmp/tshark.log.svg"
                      {:regions regions :legend legend})


  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (tagged-literal (symbol tag) form))
  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (tagged-literal (symbol tag) form))
  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (tagged-literal (symbol tag) form))

  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (apply mapv vector form))
  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (apply mapv vector form))
  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (apply mapv vector form))

  (defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[v e a t added] form]
        (mapv #(zipmap [:e :a :v :t :added]  %&) e a v t added))))

  (defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[index-tdata segment-id _ datom-count] form]
        (mapv #(zipmap [:first-datom :seg-id :datom-count] %&) (:form index-tdata) segment-id datom-count))))

  (defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
    (tagged-literal
      (symbol tag)
      (let [[index-tdata dir-id] form]
        (mapv #(zipmap [:first-datom :dir-id] %&) (:form index-tdata) dir-id))))

  ;; `draw` is called here, once, right before handing events to write-svg! --
  ;; not by any of the protocol parsers above.
  (diagram/write-svg! (map draw events) "/tmp/tshark.log.svg"
                      {:port-names port-names :legend legend}))

