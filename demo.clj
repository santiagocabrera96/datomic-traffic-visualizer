(require '[setup :refer :all]
         '[datomic.api :as d]
         '[tshark])

;; pids/port-owners only make sense once all three processes exist, so
;; there's no partial start. TSHARK_LOG lets scripts/capture.sh's own log
;; path drive this without editing code -- run that script, in its own
;; terminal, before this one so tshark sees the initial TCP handshakes too.
(def session (start-all! (or (System/getenv "TSHARK_LOG") "/tmp/tshark.log")))

(def db-uri "datomic:ddb-local://localhost:8000/datomic/caching-demo?aws_access_key_id=local&aws_secret_key=local")

(def schema
  [{:db/ident       :item/id
    :db/valueType   :db.type/long
    :db/unique      :db.unique/identity
    :db/cardinality :db.cardinality/one}
   {:db/ident       :item/name
    :db/valueType   :db.type/string
    :db/cardinality :db.cardinality/one}
   {:db/ident       :item/payload
    :db/valueType   :db.type/string
    :db/cardinality :db.cardinality/one}])

(region (d/create-database db-uri))
(def conn (region (d/connect db-uri)))
@(region (d/transact conn schema))

;; A sweep across the rest of the Datomic peer API, so a capture can be
;; validated against every shape of traffic the pipeline needs to decode
;; (not just create/connect/transact above). Each form's wrapped in `region`
;; so it shows up labeled in the diagram.

;; Writes -- more item/id's so the queries below have something to chew on.
(region @(d/transact conn [{:item/id 1 :item/name "item-1" :item/payload "abc"}]))
(region @(d/transact conn [{:item/id 2 :item/name "item-2" :item/payload "abc"}
                           {:item/id 3 :item/name "item-3"}]))
(region @(d/transact-async conn [{:item/id 4 :item/name "item-4"}]))
;; Retract an attribute, then a whole entity.
(region @(d/transact conn [[:db/retract [:item/id 3] :item/name "item-3"]]))
(region @(d/transact conn [[:db/retractEntity [:item/id 4]]]))

(def db (region (d/db conn)))
;; Reads: query.
(region (d/q '[:find ?e :where [?e :item/id]] db))
(region (d/q '[:find ?id ?name :in $ ?id :where [?e :item/id ?id] [?e :item/name ?name]]
             db 1))
(region (d/q '[:find (count ?e) :where [?e :item/id]] db))

;; Reads: pull/pull-many, entity/touch.
(region (d/pull db '[*] [:item/id 1]))
(region (d/pull-many db '[*] [[:item/id 1] [:item/id 2]]))
(region (d/touch (d/entity db [:item/id 1])))

;; Reads: raw datoms/index access.
(region (into [] (d/datoms db :aevt :item/id)))
(region (into [] (d/index-range db :item/id nil nil)))
(region (d/entid db [:item/id 1]))

;; Time travel: as-of/since/history, each queried the same way as `db`.
(region (d/q '[:find ?e :where [?e :item/id]] (d/as-of db (d/basis-t db))))
(region (d/q '[:find ?e :where [?e :item/id]] (d/since db (d/basis-t db))))
(region (d/q '[:find ?e ?v :where [?e :item/id ?v]] (d/history db)))

;; `with`: speculative transact against a db value, no transactor round-trip.
(region (d/q '[:find ?e :where [?e :item/id]]
             (:db-after (d/with db [{:item/id 5 :item/name "item-5"}]))))

;; Log/tx-range: the transaction log itself, not just entity state.
(region (into [] (d/tx-range (d/log conn) nil nil)))

;; From @alex: Transactor will go put segments in memcache before announcing
;; that an indexing job happened. Trigger one explicitly, rather than
;; waiting for its usual schedule, so the capture sees that write.
(region "Indexing job"
        (do (d/request-index conn)
            (Thread/sleep 3000)))

;; Render the capture into a sequence diagram. :since skips DynamoDB
;; Local/memcached/transactor startup noise below `session`'s start time.
(tshark/draw-diagram! (:tshark-log session) {:since (:since session)})

;; Tear the stack down -- stop tshark's capture (Ctrl-C, in its own
;; terminal) before or after this, it doesn't matter.
(region (d/delete-database db-uri))
(stop-all! session)
