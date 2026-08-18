(ns tshark-test
  (:require [charred.api :as charred]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [fressian-decode]
            [tshark :refer [decode-protocol read-tshark remove-noise]]
            [utils :refer [some-vals hex-payload->bytes update-in-if-present unpack-7bit-lsb ->vec]]))

; TODO: Where would it make sense to have event->draw, attach-participants, and decode-datomic shapes?
;; How to decode a protocol is user specific.
;; Making that parsed event to something drawable is user specific.
;; atttach-participants is linked with running processes locally. We might run in different hosts and use hostnames for
;; the names, so how to move from events to :from/:to values is user specific.
;; In different ports we might have different colors, like 5XX http responses. So it also is user specific.
;; The fact that this use case uses datomic is also specific for this example.
;; The regions is diagram specific, we just provide an aid with saving the regions somewhere.

(defn event->draw [event]
  (cond (:memcache event) (let [{:keys [key operation payload]} (:memcache event)]
                            (assoc event
                              :tag (str (name operation) " " key)
                              :note payload
                              :color "#FDFF94"))
        (:dynamodb event) (let [{:keys [operation key body status]} (:dynamodb event)]
                            (assoc event
                              :tag  (if operation (str operation " " key) (str status))
                              :note body
                              :color "#FFAEFB"))
        (:http event)      (let [{:keys [request-method uri status headers body]} (:http event)]
                             (assoc event
                               :tag  (or (some-> request-method name str/upper-case (str " " uri)) (str status))
                               :note {:headers headers
                                      :body body}
                               :color "#94C9FF"))
        (:tcp event)       (let [{:keys [flags payload]} (:tcp event)]
                             (assoc event
                               :tag (str/join "," (map name (filter flags [:URG :ACK :PSH :RST :SYN :FIN])))
                               :note (String. payload)
                               :color "#D3D3D3"))))

(defn attach-participants
  "Adds :from/:to to each event, naming its :tcp src-port/dst-port via
   `port->name` -- a port missing from it becomes :unknown-<port>."
  [port->name event]
  (let [{:keys [src-port dst-port]} (:tcp event)]
    (assoc event
      :from (port->name src-port (keyword (str "unknown-" src-port)))
      :to   (port->name dst-port (keyword (str "unknown-" dst-port))))))

(defn decode-datomic-known-shapes
  "`readers` is passed straight through to fressian-decode/decode-body, for
   custom decoding of Datomic index tags (e.g. index-tdata) -- see
   datomic-index-readers below for the real ones."
  ([event] (decode-datomic-known-shapes {} event))
  ([readers event]
   (cond
     (seq (:payload (:memcache event)))
     (update-in event [:memcache :payload] (partial fressian-decode/decode-body readers))

     (#{"pod-standby" "pod-coord"} (:S (:id (:Item (:body (:dynamodb event))))))
     (update-in-if-present event [:dynamodb :body :Item :key :S] edn/read-string)

     (some-> (:S (:id (:Item (:body (:dynamodb event))))) parse-uuid)
     (update-in-if-present event [:dynamodb :body :Item :v :S]
                            (comp (partial fressian-decode/decode-body readers) unpack-7bit-lsb))

     :else event)))

(comment
  (require '[diagram])
  ; Read tshark, try to decode per protocol if it has port->protocol, otherwise parse as :tcp.
  ; Remove noise, assuming request/response in order.
  ; Decode datomic known shapes.
  ; Events -> {:tag :note :color :from :to} In two parts, ports->from-to and events->tag-note-color
  ; Draw diagram with legend and regions.

  (defmethod decode-protocol :pepe [_ record]
    [{:hello :world}])
  (read-tshark (->> [{:timestamp "1"
                      :layers    {:tcp {:tcp_tcp_srcport "123"
                                        :tcp_tcp_dstport "12"
                                        :tcp_tcp_payload "00:01"
                                        :tcp_tcp_len     "2"
                                        :tcp_tcp_stream  "1"}}}]
                    (map charred/write-json-str)
                    (str/join "\n")))
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
  (def datomic-index-readers
    {"index-tdata"
     (fn [tag form]
       (tagged-literal
         (symbol tag)
         (let [[v e a t added] form]
           (mapv #(zipmap [:e :a :v :t :added] %&) e a v t added))))

     "index-dir-node"
     (fn [tag form]
       (tagged-literal
         (symbol tag)
         (let [[index-tdata segment-id _ datom-count] form]
           (mapv #(zipmap [:first-datom :seg-id :datom-count] %&) (:form index-tdata) segment-id datom-count))))

     "index-root-node"
     (fn [tag form]
       (tagged-literal
         (symbol tag)
         (let [[index-tdata dir-id] form]
           (mapv #(zipmap [:first-datom :dir-id] %&) (:form index-tdata) dir-id))))})

  (def events
    (->> tshark-records
         (remove-noise (comp #{"pod-coord"} :key :dynamodb))
         (map (partial decode-datomic-known-shapes datomic-index-readers))))
  (def port-names (clojure.edn/read-string (slurp "/tmp/tshark.log.ports.edn")))
  (def regions (clojure.edn/read-string (slurp "/tmp/tshark.log.regions.edn")))
  (def legend
    [{:color "#FFAEFB" :label "Storage (DynamoDB)"}
     {:color "#FDFF94" :label "Cache (memcached)"}
     {:color "#D3D3D3" :label "TCP"}
     {:color "#94C9FF" :label "HTTP"}])

  ; Regions, needed and orthogonal, is naming sections of the diagram by timestamp.
  ; port->name, optional, not needed.
  (diagram/write-svg! (map (comp event->draw (partial attach-participants port-names)) events) "/tmp/tshark.log.svg"
                      {:regions regions :legend legend}))

