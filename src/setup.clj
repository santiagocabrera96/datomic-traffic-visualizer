(ns setup
  "Datomic-specific process orchestration, on top of session's generic
  pid/port-registration core: runs local DynamoDB Local + memcached + Datomic
  transactor, connects a peer, transacts the schema -- all as a side effect
  of the top-level forms at the bottom, no -main. Installation/download
  stays in scripts/setup.sh."
  (:require [clojure.java.shell :as shell]
            [session :as session :refer [region]])
  (:import [java.io File]
           [java.net Socket]))

(def ^:private datomic-version (or (System/getenv "DATOMIC_VERSION") "1.0.7075"))
(def ^:private dest-dir (or (System/getenv "DEST_DIR") (System/getProperty "user.dir")))
(def ^:private datomic-home (or (System/getenv "DATOMIC_HOME") (str dest-dir "/datomic-pro-" datomic-version)))
(def ^:private memcached-port (Integer/parseInt (or (System/getenv "MEMCACHED_PORT") "11211")))
(def ^:private dynamodb-port (Integer/parseInt (or (System/getenv "DYNAMODB_PORT") "8000")))
(def ^:private dynamodb-local-dir (or (System/getenv "DYNAMODB_LOCAL_DIR") (str dest-dir "/dynamodb-local")))

(defn start-memcached!
  "Run memcached -vv on MEMCACHED_PORT (default 11211), stdout inherited."
  []
  (let [proc (-> (ProcessBuilder. ["memcached" "-vv" "-p" (str memcached-port)])
                 (.inheritIO)
                 .start)]
    (session/register-pid! :memcached (.pid proc))
    proc))

(defn start-dynamodb-local!
  "Run AWS's DynamoDBLocal.jar (see scripts/setup.sh) on DYNAMODB_PORT (default
  8000). -sharedDb: without it DynamoDB Local scopes tables per
  (region, access-key), so a table made via a different `aws` profile would
  be invisible to the transactor's dummy `local` credentials."
  []
  (let [proc (-> (ProcessBuilder. ["java"
                                   (str "-Djava.library.path=" dynamodb-local-dir "/DynamoDBLocal_lib")
                                   "-jar" (str dynamodb-local-dir "/DynamoDBLocal.jar")
                                   "-port" (str dynamodb-port)
                                   "-inMemory" "-sharedDb"])
                 (.inheritIO)
                 .start)]
    (session/register-pid! :dynamodb (.pid proc))
    proc))

(def ^:private ddb-local-env
  {"AWS_ACCESS_KEY_ID" "local" "AWS_SECRET_ACCESS_KEY" "local" "AWS_REGION" "us-east-1"})

(defn- ensure-transactor-table!
  "Creates the transactor's storage table (idempotently) via `bin/datomic
  ensure-transactor` -- without it, the transactor comes up but dies on its
  first storage read/write with ResourceNotFoundException. Requires DynamoDB
  Local to already be listening on `dynamodb-port`."
  []
  (let [config (str datomic-home "/config/transactor-ddb.properties")
        {:keys [exit out err]} (shell/sh "bin/datomic" "ensure-transactor" config config
                                         :dir datomic-home
                                         :env (merge {"PATH" (System/getenv "PATH")} ddb-local-env))]
    (when-not (zero? exit)
      (throw (ex-info "ensure-transactor failed" {:exit exit :out out :err err})))))

(defn start-transactor-ddb!
  "Run the Datomic transactor against transactor-ddb.properties, pointed at
  DynamoDB Local. Dummy AWS creds supplied via env since DynamoDB Local
  doesn't check them but the SDK still requires some."
  []
  (ensure-transactor-table!)
  (let [builder (-> (ProcessBuilder. ["bin/transactor" (str datomic-home "/config/transactor-ddb.properties")])
                    (.directory (File. ^String datomic-home))
                    (.inheritIO))
        env (.environment builder)]
    (.putAll env ddb-local-env)
    (let [proc (.start builder)]
      (session/register-pid! :transactor (.pid proc))
      proc)))

(defn- destroy-on-shutdown! [^Process proc label]
  (.addShutdownHook (Runtime/getRuntime)
                    (Thread. ^Runnable
                             (fn []
                               (println "Stopping" label)
                               (.destroy proc)))))

(defn- wait-for-port!
  "Block until something is listening on `port`, or throw after timeout-ms."
  [port timeout-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (if (try (.close (Socket. "localhost" (int port))) true
               (catch Exception _ false))
        nil
        (if (< (System/currentTimeMillis) deadline)
          (do (Thread/sleep 200) (recur))
          (throw (ex-info (str "Timed out waiting for port " port) {:port port})))))))

(defn start-all!
  "Starts dynamodb local, memcached, and the transactor, and wires up (via
  session/start!) capture of port ownership + regions against
  `tshark-log-file` -- the log a customer's own tshark capture (see
  scripts/capture.sh's TSHARK_LOG) is writing to. Returns {:since ...
  :tshark-log ... :ports-path ... :regions-path ... :dynamodb ... :memcached
  ... :transactor ...} rather than def'ing anything -- the caller decides
  what (if anything) to hold onto."
  [tshark-log-file]
  (let [sess (session/start! tshark-log-file)
        _ (session/register-pid! :peer (.pid (java.lang.ProcessHandle/current)))
        dynamodb (start-dynamodb-local!)
        _ (destroy-on-shutdown! dynamodb "dynamodb")
        _ (wait-for-port! dynamodb-port 10000)
        memcached (start-memcached!)
        _ (destroy-on-shutdown! memcached "memcached")
        transactor (region (start-transactor-ddb!))
        _ (destroy-on-shutdown! transactor "transactor")
        _ (wait-for-port! 4336 20000)]
    (assoc sess :dynamodb dynamodb :memcached memcached :transactor transactor)))

(defn stop-all!
  "Tears down a `session` map returned by start-all! -- destroys the
  dynamodb/memcached/transactor processes and, via session/stop!, removes
  the port-owners/regions add-watches session/start! added (so a later
  start-all! isn't spitting to a now-stopped session's paths)."
  [{:keys [dynamodb memcached transactor] :as sess}]
  (session/stop! sess)
  (.destroy ^Process transactor)
  (.destroy ^Process memcached)
  (.destroy ^Process dynamodb))

(comment
  ;; Runs as soon as this namespace loads -- pids/port-owners only make sense
  ;; once all three processes exist, so there's no partial start. TSHARK_LOG
  ;; lets scripts/capture.sh's own log path drive this without editing code.
  (def session (start-all! (or (System/getenv "TSHARK_LOG") "/tmp/tshark.log")))

  (require '[datomic.api :as d])

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

  ;; From here, the REPL is ready -- run your own queries/transactions, e.g.:
  ;;   (region @(d/transact conn [{:item/id 1 :item/name "item-1"}]))
  ;;   (region (d/pull (d/db conn) '[*] [:item/id 1]))
  ;; wrapping a call in `region` labels its traffic in events.svg with that
  ;; exact code. Then, once tshark's capture (scripts/capture.sh, run
  ;; beforehand in its own terminal) has what you want:
  ;;   (require 'process)
  ;;   (process/write-diagram! {:since since :ignore-pod-coord? true})

  (require 'process)
  (def ports {8000 :dynamodb, 11211 :memcache})
  (process/draw-diagram! ports "/tmp/tshark.log" {:port-names {55675 :transactor}})
  (process/draw-diagram! ports (:tshark-log session) {:since (:since session)})
  (def since (System/currentTimeMillis))
  (region @(d/transact conn [{:item/id 1 :item/name "item-1"}]))
  (process/draw-diagram! ports (:tshark-log session) {:since since})

  ; From @alex: Transactor will go put segments in memcache before announcing that an indexing job happened.

  ;; Manual teardown.
  (d/delete-database db-uri)
  (stop-all! session))
