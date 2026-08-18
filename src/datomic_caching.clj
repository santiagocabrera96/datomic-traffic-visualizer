(ns datomic-caching
  "This example, end to end: read a tshark capture of Datomic peer traffic
   (over memcache/http/dynamodb), pair off noisy transactor heartbeats,
   decode Datomic's fressian-tagged shapes, and render the result as a
   PlantUML sequence diagram. Everything below is specific to *this* use
   case -- which protocol/colors/participant-names/Datomic shapes matter --
   and is deliberately kept separate from tshark.clj/diagram.clj/
   fressian_decode.clj, which stay Datomic-agnostic and reusable as-is for
   a different capture."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [dynamodb]
            [fressian-decode]
            [http]
            [memcache]
            [tshark :refer [read-tshark remove-noise]]
            [utils :refer [update-in-if-present unpack-7bit-lsb]]))

(defn event->draw
  "Adds :tag/:note/:color per protocol. The cond order matters: on real
   input a dynamodb event is also an http event (dynamodb/http->dynamodb
   assoc's :dynamodb onto one), which is also a tcp event (http/tshark-tcp->http
   assoc's :http onto one) -- likewise a memcache event is also a tcp event.
   So :tcp/:http/:dynamodb (or :tcp/:memcache) are present simultaneously, and
   checking the more specific protocol first is what makes a dynamodb event
   draw pink instead of falling through to blue (http) or grey (tcp)."
  [event]
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
   datomic-index-readers below for the real ones.

   Two DynamoDB row shapes get special-cased here because their :S values
   aren't plain scalars:
   - pod-standby/pod-coord (the transactor's heartbeat rows, identified by
     :id) store their :key as a printed EDN vector, e.g.
     \"[host pid transactor-id peer-id ts version flag generation]\" --
     edn/read-string undoes that.
   - any other row keyed by a UUID stores its :v pre-packed 7 bits per
     byte, LSB-first (see utils/unpack-7bit-lsb), so the whole string stays
     within DynamoDB's ASCII-safe string type; unpacking then fressian-
     decoding recovers the real value."
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

(def datomic-index-readers
  "fressian-decode readers for Datomic's index-tagged shapes, each stored
   column-wise (one array per field, e.g. all :e values then all :a values)
   rather than row-wise -- these zip the parallel columns back into a
   vector of row maps, which is what the rest of this codebase (and a
   human skimming the diagram) actually wants to read."
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

(defn read-datomic-capture
  "Reads `tshark-log` (path or raw content -- see read-tshark), decodes it
   per `port->protocol` (values must each name a registered decode-protocol
   method -- :tcp/:http/:dynamodb/:memcache are registered by tshark/http/
   dynamodb/memcache respectively; defaults to this demo's ports), drops the
   transactor's own pod-coord/pod-standby heartbeat traffic, and decodes
   Datomic's known fressian shapes (see decode-datomic-known-shapes;
   `readers` customizes e.g. index-tdata decoding). `since`/`until` are
   passed straight through to read-tshark. This is what demo.clj calls.
   Doesn't yet touch ports/regions files -- callers still resolve :from/:to
   (attach-participants) and diagram regions themselves."
  [tshark-log & {:keys [readers port->protocol since until]
                 :or   {readers datomic-index-readers port->protocol {8000 :dynamodb 11211 :memcache}}}]
  (->> (read-tshark tshark-log :port->protocol port->protocol :since since :until until)
       (remove-noise (comp #{"pod-coord" "pod-standby"} :key :dynamodb))
       (map (partial decode-datomic-known-shapes readers))))

(comment
  ;; event->draw, one plain event per protocol branch -- no capture file
  ;; needed, these are just the shapes memcache/dynamodb/http/tshark's
  ;; decode-protocol methods produce.
  (event->draw {:memcache {:operation :get :key "foo" :payload "bar"}})
  ;;=> tag "get foo", note "bar", color #FDFF94 (yellow)
  (event->draw {:dynamodb {:operation "PutItem" :key "abc" :body {:x 1}}})
  ;;=> tag "PutItem abc", note {:x 1}, color #FFAEFB (pink)
  (event->draw {:dynamodb {:status 200}})
  ;;=> no :operation (a response) -- tag falls back to "200"
  (event->draw {:http {:request-method :get :uri "/foo" :headers {} :body nil}})
  ;;=> tag "GET /foo", color #94C9FF (blue)
  (event->draw {:tcp {:flags #{:SYN :ACK} :payload (byte-array (map byte "hi"))}})
  ;;=> tag "ACK,SYN", note "hi", color #D3D3D3 (grey)

  ;; attach-participants: a known port resolves by name, an unknown one
  ;; becomes :unknown-<port> instead of nil.
  (attach-participants {8000 :storage} {:tcp {:src-port 8000 :dst-port 9999}})
  ;;=> {:from :storage :to :unknown-9999, ...}

  ;; decode-datomic-known-shapes's three special-cased shapes.
  (require '[clojure.data.fressian :as fressian])
  (decode-datomic-known-shapes
    {:memcache {:payload (let [buf (fressian/write "hello")
                               arr (byte-array (.remaining buf))]
                           (.get buf arr)
                           arr)}})
  ;;=> :memcache :payload fressian-decoded to "hello"
  (decode-datomic-known-shapes
    {:dynamodb {:body {:Item {:id {:S "pod-coord"} :key {:S "[\"host\" 1 2]"}}}}})
  ;;=> :dynamodb :body :Item :key :S edn/read-string'd to ["host" 1 2]
  (decode-datomic-known-shapes {:http {:status 200}})
  ;;=> matches none of the three shapes -- returned untouched (:else)

  (require '[diagram])
  ;; The real pipeline, depending on an actual capture at /tmp/tshark.log --
  ;; see tshark.clj's own comment block for a synthetic-input version of
  ;; read-tshark itself.
  (def tshark-records (read-tshark "/tmp/tshark.log"
                                   :port->protocol {8000  :dynamodb
                                                    11211 :memcache}))
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

  ; regions names sections of the diagram by timestamp; port-names is
  ; optional (attach-participants falls back to :unknown-<port> without it).
  (diagram/write-svg! (map (comp event->draw (partial attach-participants port-names)) events) "/tmp/tshark.log.svg"
                      {:regions regions :legend legend}))

