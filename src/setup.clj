(ns setup
  "Runs local DynamoDB Local + memcached + Datomic transactor, connects a peer,
  transacts the schema -- all as a side effect of the top-level forms at the
  bottom, no -main. Installation/download stays in scripts/setup.sh."
  (:require [clojure.java.shell :as shell]
            [clojure.string :as str])
  (:import [java.io File]
           [java.net Socket]))

;; The atoms below are defonce'd so re-evaluating this file at the REPL
;; doesn't clobber them (or the add-watches attached below) and lose state
;; already recorded.

(def ^:private datomic-version (or (System/getenv "DATOMIC_VERSION") "1.0.7075"))
(def ^:private dest-dir (or (System/getenv "DEST_DIR") (System/getProperty "user.dir")))
(def ^:private datomic-home (or (System/getenv "DATOMIC_HOME") (str dest-dir "/datomic-pro-" datomic-version)))
(def ^:private memcached-port (Integer/parseInt (or (System/getenv "MEMCACHED_PORT") "11211")))
(def ^:private dynamodb-port (Integer/parseInt (or (System/getenv "DYNAMODB_PORT") "8000")))
(def ^:private dynamodb-local-dir (or (System/getenv "DYNAMODB_LOCAL_DIR") (str dest-dir "/dynamodb-local")))

(defonce ^{:doc "This session's process pids, keyed by :dynamodb/:memcached/:transactor/:peer."}
  pids
  (atom {:peer (.pid (java.lang.ProcessHandle/current))}))

(defonce ^{:doc "Local TCP port -> owner name (from `pids`), per the last lsof sweep."}
  port-owners
  (atom {}))

(defonce ^{:doc "This session's {:label ... :start ... :end ...} regions, one per `region` call."}
  regions
  (atom []))

(defmacro region
  "Runs body, recording {:label ... :start ... :end ...} in `regions` for the
  wall-clock window it took, then returns body's value like `do`. Label
  defaults to the printed source of body; pass an explicit string first to
  override."
  [& body]
  (let [[label forms] (if (string? (first body))
                        [(first body) (rest body)]
                        [(pr-str (if (= 1 (count body)) (first body) (cons 'do body))) body])]
    `(let [start# (System/currentTimeMillis)
           result# (do ~@forms)]
       (swap! regions conj {:label ~label :start start# :end (System/currentTimeMillis)})
       result#)))

(defn- lsof-ports
  "Local TCP ports `pid` currently holds, per `lsof -Fn`."
  [pid]
  (->> (shell/sh "lsof" "-a" "-p" (str pid) "-iTCP" "-P" "-n" "-Fn")
       :out
       str/split-lines
       (keep (fn [line]
               (when (str/starts-with? line "n")
                 (-> (subs line 1) (str/split #"->") first (str/split #":") peek parse-long))))))

(defn refresh-ports!
  "One lsof sweep over every pid in `pids`, merged into `port-owners`."
  []
  (doseq [[name pid] @pids
          :when pid
          port (lsof-ports pid)]
    (swap! port-owners assoc port name)))

(defn owner
  "Who holds `port` right now; sweeps once first if not yet known."
  [port]
  (or (@port-owners port)
      (do (refresh-ports!) (@port-owners port))))

(defn start-port-watcher!
  "Background daemon thread sweeping `port-owners` every `interval-ms` (default 200)."
  ([] (start-port-watcher! 40))
  ([interval-ms]
   (doto (Thread. ^Runnable (fn [] (while true (refresh-ports!) (Thread/sleep interval-ms))))
     (.setDaemon true)
     .start)))

(defn start-memcached!
  "Run memcached -vv on MEMCACHED_PORT (default 11211), stdout inherited."
  []
  (let [proc (-> (ProcessBuilder. ["memcached" "-vv" "-p" (str memcached-port)])
                 (.inheritIO)
                 .start)]
    (swap! pids assoc :memcached (.pid proc))
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
    (swap! pids assoc :dynamodb (.pid proc))
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
      (swap! pids assoc :transactor (.pid proc))
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
  "Starts dynamodb local, memcached, and the transactor, and wires up capture
  of port ownership + regions against `tshark-log-file` -- the log a
  customer's own tshark capture (see scripts/capture.sh's TSHARK_LOG) is
  writing to. Returns {:since ... :tshark-log ... :ports-path ...
  :regions-path ... :dynamodb ... :memcached ... :transactor ...} rather than
  def'ing anything -- the caller decides what (if anything) to hold onto."
  [tshark-log-file]
  (let [since (System/currentTimeMillis)                    ; startup noise below `since` isn't peer traffic
        ports-path (str tshark-log-file ".ports.edn")
        regions-path (str tshark-log-file ".regions.edn")
        ;; Keeps the on-disk mapping in sync: every swap! re-dumps it, so it
        ;; outlives this REPL session without a separate manual save step.
        _ (add-watch port-owners ::dump-on-change #(spit ports-path (pr-str %4)))
        _ (add-watch regions ::dump-on-change #(spit regions-path (pr-str %4)))
        _ (start-port-watcher!)
        dynamodb (start-dynamodb-local!)
        _ (destroy-on-shutdown! dynamodb "dynamodb")
        _ (wait-for-port! dynamodb-port 10000)
        memcached (start-memcached!)
        _ (destroy-on-shutdown! memcached "memcached")
        transactor (region (start-transactor-ddb!))
        _ (destroy-on-shutdown! transactor "transactor")
        _ (wait-for-port! 4336 20000)]
    {:since        since
     :tshark-log   tshark-log-file
     :ports-path   ports-path
     :regions-path regions-path
     :dynamodb     dynamodb
     :memcached    memcached
     :transactor   transactor}))

(defn stop-all!
  "Tears down a `session` map returned by start-all! -- destroys the
  dynamodb/memcached/transactor processes and removes the port-owners/regions
  add-watches (same ::dump-on-change key start-all! added them under) so a
  later start-all! isn't spitting to a now-stopped session's paths."
  [{:keys [dynamodb memcached transactor]}]
  (remove-watch port-owners ::dump-on-change)
  (remove-watch regions ::dump-on-change)
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
