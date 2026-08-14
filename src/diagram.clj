(ns diagram
  "Renders a PlantUML sequence diagram from a timestamp-sorted log of traffic
   events (flat maps with :srcport/:dstport -- :from/:to participant names
   are resolved here from opts' :port-names)."
  (:require [clojure.java.io :as io]
            [clojure.pprint :as pp]
            [clojure.string :as str])
  (:import [net.sourceforge.plantuml SourceStringReader FileFormat FileFormatOption]
           [java.io ByteArrayOutputStream]))

;; pprint has no structural dispatch for tagged literals (fressian-decode's
;; #index-tdata/...), so it prints them as one flat line -- recurse into :form.
(defmethod pp/simple-dispatch clojure.lang.TaggedLiteral [tl]
  (pp/pprint-logical-block :prefix (str "#" (:tag tl) " ")
                           (pp/write-out (:form tl))))

(defn- fmt-participant [x]
  (if (keyword? x) (name x) (str x)))

(defn- resolve-port
  "port-names entry for `port`, or :unknown-<port> when it's not in the map --
   e.g. a port never swept by setup's port-owner watcher."
  [port-names port]
  (port-names port (keyword (str "unknown-" port))))

(defn- attach-participants
  "Fills in an event's :from/:to from its :srcport/:dstport via port-names,
   but only when missing -- an event that already names its participants
   (e.g. built by a caller that doesn't have ports) is left alone."
  [port-names event]
  (cond-> event
    (not (contains? event :from)) (assoc :from (resolve-port port-names (:srcport event)))
    (not (contains? event :to))   (assoc :to   (resolve-port port-names (:dstport event)))))

(def ^:private max-line-length 200)

(defn- wrap-line [line]
  (->> (partition-all max-line-length line)
       (map (partial apply str))
       (str/join "\n")))

(defn- strip-invalid-xml-chars
  "XML 1.0 forbids most C0 control chars (e.g. \\u000b in an un-decoded raw
   body); left in, they break SVG serialization for the whole diagram."
  [s]
  (str/replace s #"[\x00-\x08\x0B\x0C\x0E-\x1F]" "?"))

(defn- fmt-note
  "Joins note lines into PlantUML's one-line `note over` format, escaping
   newlines and [ ] (PlantUML's creole parser reads [[...]] as a link, which
   pretty-printed nested vectors trigger constantly)."
  [lines]
  (->> lines
       (mapcat str/split-lines)
       (map wrap-line)
       (str/join "\n")
       strip-invalid-xml-chars
       (#(str/replace % "\n" "\\n"))
       (#(str/replace % "[" "~["))
       (#(str/replace % "]" "~]"))))

(defn- has-content?
  "True if body is non-nil and, when a collection/string, non-empty. Can't
   just call `seq` unconditionally -- a fressian-decoded body can be a
   non-Seqable value (e.g. a bare TaggedLiteral), which throws in `seq`."
  [body]
  (cond
    (nil? body) false
    (or (coll? body) (string? body)) (boolean (seq body))
    :else true))

(defn- note-lines
  "Pretty-prints :body when there's anything in it, else nil (no note). A raw
   byte array (memcache body that didn't fressian-decode) renders as a byte
   count plus :decode-error instead of being pprinted."
  [{:keys [body decode-error]}]
  (cond
    (bytes? body)
    [(str "<" (alength ^bytes body) " raw bytes>"
          (when decode-error (str " (decode error: " decode-error ")")))]

    (has-content? body)
    [(str/trim (with-out-str (pp/pprint body)))]))

(defn- default-label
  [{:keys [operation key status]}]
  (str (or operation "message")
       (when key (str " " key))
       (when status (str " " status))))

(defn- event-color [protocol-styles event]
  (:color (protocol-styles (:protocol event))))

(defn- legend-lines
  "One `|<back:color>    </back>| label |` row per entry in `protocol-styles`
   ({protocol -> {:color \"#...\" :label \"...\"}})."
  [protocol-styles]
  (for [[_ {:keys [color label]}] protocol-styles]
    (format "|<back:%s>    </back>| %s |" color label)))

(defn- event->plantuml
  [label-fn protocol-styles event]
  (let [[from to] (map fmt-participant [(:from event) (:to event)])
        lines     (note-lines event)
        color     (event-color protocol-styles event)]
    (str/join "\n"
              (remove nil?
                      [(format "\"%s\" -> \"%s\"%s: %s" from to (if color (str " " color) "")
                               (strip-invalid-xml-chars (label-fn event)))
                       (when (seq lines)
                         (format "note over \"%s\", \"%s\"%s: %s" from to (if color (str " " color) "")
                                 (fmt-note lines)))]))))

(defn- region-for
  "Which of `regions` (if any) `ts` falls in. Regions are assumed disjoint."
  [regions ts]
  (some (fn [r] (when (<= (:start r) ts (:end r)) r)) regions))

(defn- fmt-group-label
  "Same escaping as fmt-note, collapsed to one line (`group <label>` is single-line)."
  [label]
  (-> label
      strip-invalid-xml-chars
      (str/replace #"\s+" " ")
      (str/replace "[" "~[")
      (str/replace "]" "~]")))

(defn- grouped-lines
  "Wraps contiguous runs of `event-lines` (1:1 with `events`) in
   `group <label> ... end` per `regions`, keyed by each event's :timestamp.
   Regions are assumed disjoint -- this emits one flat group per run, not
   real nesting."
  [regions events event-lines]
  ;; keyed on the region map, not just :label -- two disjoint regions can
  ;; share a label and must still open/close separately.
  (loop [pairs (map vector events event-lines), current nil, acc []]
    (if (empty? pairs)
      (cond-> acc current (conj "end"))
      (let [[event line] (first pairs)
            region       (region-for regions (:timestamp event))]
        (if (= region current)
          (recur (rest pairs) current (conj acc line))
          (recur (rest pairs) region
                 (cond-> acc
                         current (conj "end")
                         region (conj (str "group " (fmt-group-label (:label region))))
                         true (conj line))))))))

(defn events->plantuml
  "events need not be pre-sorted; sorted by :timestamp here. Any event
   missing :from/:to gets them resolved from its :srcport/:dstport via opts'
   :port-names; an event that already has :from/:to is left alone.

   opts: {:title           \"...\"                 diagram title
          :label-fn        (fn [event] \"...\")    arrow label, defaults to `default-label`
          :port-names      {port -> name}          resolves :srcport/:dstport into
                            participant names (e.g. setup's port-owners map)
                            for events missing :from/:to; a port missing from it
                            renders as :unknown-<port>
          :regions         [{:label \"...\" :start ms :end ms}]  wraps events whose
                            :timestamp falls in [:start :end] in `group :label ... end`
          :protocol-styles {protocol -> {:color \"#...\" :label \"...\"}}  colors
                            that protocol's arrows/notes and lists it in the
                            legend; a protocol missing from it gets no color
                            and no legend line}"
  ([events] (events->plantuml events nil))
  ([events {:keys [title label-fn regions port-names protocol-styles]
            :or   {label-fn default-label port-names {} protocol-styles {}}}]
   (let [events       (->> events (sort-by :timestamp) (map (partial attach-participants port-names)))
         participants (->> events (mapcat (juxt :from :to)) distinct (map fmt-participant))]
     (str/join "\n"
               (remove nil?
                       (concat
                         ["@startuml"]
                         (when title [(str "title " title)])
                         ["autonumber"]
                         (map #(format "participant \"%s\"" %) participants)
                         (grouped-lines regions events (map #(event->plantuml label-fn protocol-styles %) events))
                         (when (seq (legend-lines protocol-styles))
                           (concat ["legend top left"] (legend-lines protocol-styles) ["endlegend"]))
                         ["@enduml"]))))))

(defn write-diagram!
  ([events path] (write-diagram! events path nil))
  ([events path opts]
   (spit path (events->plantuml events opts))
   path))

(defn plantuml->svg [plantuml-str]
  (let [reader (SourceStringReader. plantuml-str)
        out    (ByteArrayOutputStream.)]
    (.outputImage reader out (FileFormatOption. FileFormat/SVG))
    (.toString out "UTF-8")))

(defn write-svg!
  ([events path] (write-svg! events path nil))
  ([events path opts]
   (with-open [w (io/writer path)]
     (.write w (plantuml->svg (events->plantuml events opts))))
   path))

(comment
  ;; Minimal: events already have :from/:to, no styling. :body renders as a
  ;; `note over` under the arrow when present.
  (def events
    [{:from :peer :to :dynamodb :timestamp 1 :operation "PutItem" :key "foo"
      :body {:Item {:id "foo" :value 42}}}
     {:from :dynamodb :to :peer :timestamp 2 :status 200}])
  (println (events->plantuml events))

  ;; Same events, but naming participants by :srcport/:dstport instead --
  ;; :port-names resolves them (a port missing from the map renders as
  ;; :unknown-<port>).
  (def raw-events
    [{:srcport 49515 :dstport 8000 :timestamp 1 :operation "PutItem" :key "foo"
      :body {:Item {:id "foo" :value 42}}}
     {:srcport 8000 :dstport 49515 :timestamp 2 :status 200}])
  (println (events->plantuml raw-events {:port-names {8000 :dynamodb}}))

  ;; A title, a custom arrow label, and grouping a run of events under a
  ;; `group ... end` block (as produced by setup's `region` macro).
  (println (events->plantuml raw-events
                             {:port-names {8000 :dynamodb}
                              :title      "Demo"
                              :label-fn   (fn [e] (str (:operation e) " " (:key e)))
                              :regions    [{:label "warmup" :start 0 :end 1}]}))

  ;; Coloring/legend: pass :protocol-styles -- see dynamodb and memcache for
  ;; the real ones.
  (println (events->plantuml (map #(assoc % :protocol :dynamodb) raw-events)
                             {:port-names      {8000 :dynamodb}
                              :protocol-styles {:dynamodb {:color "#FFAEFB" :label "Storage (DynamoDB)"}}}))

  ;; Write straight to a .puml source file, or render straight to SVG --
  ;; both take the same opts as events->plantuml.
  (write-diagram! events "/tmp/events.puml")
  (write-svg! events "/tmp/events.svg" {:port-names {8000 :dynamodb}})
  (write-svg! (map #(assoc % :protocol :dynamodb) events) "/tmp/events.svg" {:port-names {8000 :dynamodb}})

  ;; The whole real pipeline lives in process -- it reads a tshark log
  ;; via protocol/read-messages, then calls write-svg! with the ports
  ;; file's port-names and (optionally) setup's regions.
  )
