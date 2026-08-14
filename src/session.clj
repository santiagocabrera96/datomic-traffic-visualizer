(ns session
  "Generic, client-agnostic session bookkeeping for a tshark capture:
   registering (label, pid) pairs, sweeping their ports via `lsof`,
   mirroring the result to a sidecar file next to the capture log, and
   tracking labeled wall-clock regions. Knows nothing about what
   processes exist or how to start/stop them -- that's the client's job
   (see setup.clj for the Datomic-specific process orchestration built on
   top of this)."
  (:require [clojure.java.shell :as shell]
            [clojure.string :as str]))

;; Defonce'd so re-evaluating this file at the REPL doesn't clobber state
;; (or the add-watches start! attaches) already recorded this session.

(defonce ^{:doc "This session's process pids, keyed by caller-supplied
                 label -- see register-pid!. Starts empty; even this JVM's
                 own pid isn't registered by default -- what to call the
                 current process (:peer, or anything else) is the
                 client's call, not something this generic namespace
                 should assume."}
  pids
  (atom {}))

(defonce ^{:doc "Local TCP port -> owner label (from `pids`), per the last lsof sweep."}
  port-owners
  (atom {}))

(defonce ^{:doc "This session's {:label ... :start ... :end ...} regions, one per `region` call."}
  regions
  (atom []))

(defn register-pid!
  "Records `pid` under `label` in `pids`, so the port watcher starts
   sweeping its ports too. The client calls this once it has actually
   started whatever process `pid` belongs to -- this namespace never
   starts a process itself."
  [label pid]
  (swap! pids assoc label pid))

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

(defn start-port-watcher!
  "Background daemon thread sweeping `port-owners` every `interval-ms` (default 200)."
  ([] (start-port-watcher! 40))
  ([interval-ms]
   (doto (Thread. ^Runnable (fn [] (while true (refresh-ports!) (Thread/sleep interval-ms))))
     (.setDaemon true)
     .start)))

(defn start!
  "Wires up capture of port ownership + regions against `tshark-log-file`
   -- the log a tshark capture (see scripts/capture.sh's TSHARK_LOG) is
   writing to -- and starts the port watcher. Returns {:since ...
   :tshark-log ... :ports-path ... :regions-path ...}, rather than
   def'ing anything, so the caller decides what (if anything) to hold
   onto. Register each client-started process's pid via register-pid!
   (before or after calling this -- the port watcher polls `pids` on
   every sweep, so order doesn't matter)."
  [tshark-log-file]
  (let [since        (System/currentTimeMillis)
        ports-path   (str tshark-log-file ".ports.edn")
        regions-path (str tshark-log-file ".regions.edn")]
    ;; Keeps the on-disk mapping in sync: every swap! re-dumps it, so it
    ;; outlives this REPL session without a separate manual save step.
    (add-watch port-owners ::dump-on-change #(spit ports-path (pr-str %4)))
    (add-watch regions ::dump-on-change #(spit regions-path (pr-str %4)))
    (start-port-watcher!)
    {:since        since
     :tshark-log   tshark-log-file
     :ports-path   ports-path
     :regions-path regions-path}))

(defn stop!
  "Removes the port-owners/regions add-watches start! added (same
   ::dump-on-change key), so a later start! isn't spitting to a
   now-stopped session's sidecar paths. Does not touch any client
   processes -- that's the client's own stop's job (see setup/stop-all!)."
  [_session]
  (remove-watch port-owners ::dump-on-change)
  (remove-watch regions ::dump-on-change))

(comment
  (def sess (start! "/tmp/tshark.log"))

  ;; Register whatever processes the client started -- session doesn't
  ;; start anything itself, only tracks pids it's told about.
  (register-pid! :some-process 12345)

  @port-owners

  (region (Thread/sleep 100))
  @regions

  (stop! sess))
