(ns process
  "Turns a tshark capture log into an SVG sequence diagram -- see draw-diagram!."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.repl :refer :all]
            [clojure.repl.deps :refer :all]
            [diagram :as diagram]
            [protocol :as proto]))
(require
  '[dynamodb]  ; Needed to load dynamodb multimethods
  '[memcache]) ; Needed to load memcache multimethods

(set! *print-length* 1000)
; First we capture information of traffic into a file
; Then we start our processes: dynamodb, memcache, transactor, and our REPL is the peer
; Capture info...
; While capturing, we want to generate a map of ports owners, and a map of regions (label, start, end) times in milliseconds.

; Then, when we process that information, we want to understand known protocols (dynamodb over http/memcache over tcp).
; Split grouped by messages into individual protocol messages.
; Then, we need to find bytearrays. Either as 7bit LSB packed string. Or string with format XX:XX:XX:XX
; We need to add types to each field, specially to know how to decode them.
; Decode bytearrays, parse edn, etc.

(defn- read-edn-if-exists [path]
  (when (.exists (io/file path))
    (edn/read-string (slurp path))))

(defn draw-diagram!
  "Reads `tshark-log-file` (as captured by scripts/capture.sh/setup's
   start-all!), resolves participant names from its sibling *.ports.edn,
   groups events by its sibling *.regions.edn when present, and writes an SVG
   sequence diagram. Remaining opts:
     :svg-path      output path, default tshark-log-file + \".svg\"
     :remove-noise? drop noisy requests (e.g. dynamo's pod-coord heartbeat)
                     via protocol/remove-noise, default true
     :port-names    extra port -> name entries, layered over the sibling
                     *.ports.edn (and overriding it on conflict) -- for ports
                     the port-owners watcher never caught (e.g. it wasn't
                     running yet, or missed a short-lived connection)
     :since         epoch-millis timestamp (e.g. setup's start-all!
                     :since) -- events before it are dropped, so a log
                     spanning several sessions only diagrams the latest one
   Any other opt (e.g. :title, :label-fn) is passed through to
   diagram/write-svg!, merged under the :port-names/:regions derived here."
  [tshark-log-file & {:keys [svg-path remove-noise? port-names since]
                       :or   {svg-path (str tshark-log-file ".svg")
                              remove-noise? true}
                       :as   opts}]
  (let [file-port-names (read-edn-if-exists (str tshark-log-file ".ports.edn"))
        regions         (read-edn-if-exists (str tshark-log-file ".regions.edn"))
        events          (cond-> (proto/read-messages tshark-log-file since)
                          remove-noise? proto/remove-noise)]
    (diagram/write-svg! events svg-path
                         (merge {:regions regions}
                                (dissoc opts :svg-path :remove-noise? :port-names :since)
                                {:port-names (merge file-port-names port-names)}))
    svg-path))

(comment
  (draw-diagram! "/tmp/tshark.log")
  (draw-diagram! "/tmp/tshark.log" :svg-path "/tmp/events.svg")
  (draw-diagram! "/tmp/tshark.log" :remove-noise? false)
  (draw-diagram! "/tmp/tshark.log" :port-names {49515 :peer})
  (draw-diagram! "/tmp/tshark.log" :since (- (System/currentTimeMillis) 10000000))
  (draw-diagram! "/tmp/tshark.log" :svg-path "/tmp/events.svg" :title "Demo"))
