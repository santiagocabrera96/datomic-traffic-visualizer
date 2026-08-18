(ns diagram
  "Renders a PlantUML sequence diagram from a timestamp-sorted log of traffic
   events (flat maps that already carry :from/:to participant names, which
   dictate the arrow's direction)."
  (:require [clojure.java.io :as io]
            [clojure.pprint :as pp]
            [clojure.string :as str])
  (:import [net.sourceforge.plantuml SourceStringReader FileFormat FileFormatOption]
           [java.awt Desktop]
           [java.io ByteArrayOutputStream]))

;; pprint has no structural dispatch for tagged literals (fressian-decode's
;; #index-tdata/...), so it prints them as one flat line -- recurse into :form.
(defmethod pp/simple-dispatch clojure.lang.TaggedLiteral [tl]
  (pp/pprint-logical-block :prefix (str "#" (:tag tl) " ")
                           (pp/write-out (:form tl))))

(defn- fmt-participant [x]
  (if (keyword? x) (name x) (str x)))

(def ^:private default-max-line-length 80)

;; PlantUML's `skinparam wrapWidth` wraps note/message text at word
;; boundaries during actual rendering (real glyph widths), so there's no
;; need to hard-wrap ordinary text ourselves -- just give it a pixel budget
;; roughly equivalent to :max-line-length characters at its default font
;; size. It only wraps at whitespace, though -- see break-long-word below.
(def ^:private px-per-char 7)

;; pr-str/pprint's own escaping of a string's non-printable chars: either a
;; \uXXXX (4 hex digit) unicode escape, or one of the 2-char short escapes
;; (\n \r \t \b \f \\ \"), or (falling through the alternation) a single
;; ordinary char. Tokenizing on this lets break-long-word insert a forced
;; line break between tokens without ever cutting one in half -- e.g.
;; splitting a \u001F escape into \u00 and 1F, which would garble it
;; into plain text.
(def ^:private escape-token-pattern #"\\u[0-9A-Fa-f]{4}|\\.|(?s).")

(defn- break-long-word
  "word, with a forced newline inserted every max-line-length chars, if it's
   over that long -- skinparam wrapWidth only wraps at whitespace, so a
   whitespace-free run (e.g. a raw binary blob's escaped bytes, with no
   real spaces to wrap at) longer than that would otherwise never wrap at
   all, blowing out the whole note's rendered width. Tokenizes on pr-str's
   escape sequences first so an inserted break never lands inside one."
  [max-line-length word]
  (if (<= (count word) max-line-length)
    word
    (->> (re-seq escape-token-pattern word)
         (reduce (fn [{:keys [out cur len]} tok]
                   (let [tlen (count tok)]
                     (if (and (pos? len) (> (+ len tlen) max-line-length))
                       {:out (conj out cur) :cur tok :len tlen}
                       {:out out :cur (str cur tok) :len (+ len tlen)})))
                 {:out [] :cur "" :len 0})
         ((fn [{:keys [out cur]}] (conj out cur)))
         (str/join "\n"))))

(defn- break-long-words
  "line, with break-long-word applied to each whitespace-delimited run --
   splitting on the zero-width boundary around \\s keeps whitespace chars
   as their own pieces (rather than consuming them), so they're rejoined
   verbatim -- ordinary short runs pass through untouched, left to
   skinparam wrapWidth to wrap normally at render time."
  [max-line-length line]
  (->> (str/split line #"(?<=\s)|(?=\s)")
       (map (partial break-long-word max-line-length))
       (apply str)))

(defn- strip-invalid-xml-chars
  "Strips C0 control chars (e.g. \\u000b in an un-decoded raw body) -- XML
   1.0 forbids most of these, and left in, they break SVG serialization for
   the whole diagram -- plus C0/C1 control chars (\\x7F-\\x9F), which are
   XML-legal but have crashed PlantUML's own note parser on a raw binary
   payload naively decoded as text."
  [s]
  (str/replace s #"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]" "?"))

(defn- fmt-note
  "Joins note lines into PlantUML's one-line `note over` format, escaping
   newlines and [ ] and leading # (PlantUML's creole parser reads [[...]] as
   a link, which pretty-printed nested vectors trigger constantly -- and
   reads a line starting with # as a numbered-list item, silently replacing
   it with an ordinal like \"1.\" and dropping the #, which a pprinted
   TaggedLiteral's own \"#tag \" prefix triggers just as constantly).
   Real newlines here are genuine logical breaks (a pretty-printed map's own
   structural line breaks) that PlantUML should always honor as a line
   break, distinct from the word-boundary visual wrapping `skinparam
   wrapWidth` handles at render time -- so unlike those, they aren't left
   for PlantUML to decide. break-long-words forces breaks into any
   whitespace-free run wider than max-line-length too -- wrapWidth alone
   leaves those untouched (e.g. a raw binary blob's escaped bytes, with no
   spaces to wrap at), which blows out the whole note's rendered width
   instead of wrapping."
  [max-line-length lines]
  (->> lines
       (map (partial break-long-words max-line-length))
       (str/join "\n")
       strip-invalid-xml-chars
       (#(str/replace % "\n" "\\n"))
       (#(str/replace % "[" "~["))
       (#(str/replace % "]" "~]"))
       (#(str/replace % "#" "~#"))))

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
  "Pretty-prints :note when there's anything in it, else nil (no note). A raw
   byte array (memcache body that didn't fressian-decode) renders as a byte
   count plus :decode-error instead of being pprinted."
  [{:keys [note decode-error]}]
  (cond
    (bytes? note)
    [(str "<" (alength ^bytes note) " raw bytes>"
          (when decode-error (str " (decode error: " decode-error ")")))]

    (has-content? note)
    [(str/trim (with-out-str (pp/pprint note)))]))

(defn- default-label
  [{:keys [tag]}]
  (str tag))

(def ^:private default-color "#D3D3D3")

(defn- event-color [event]
  (or (:color event) default-color))

(defn- legend-lines
  "One `|<back:color>    </back>| label |` row per entry in `legend`
   ([{:color \"#...\" :label \"...\"} ...])."
  [legend]
  (for [{:keys [color label]} legend]
    (format "|<back:%s>    </back>| %s |" color label)))

(defn- event->plantuml
  [label-fn max-line-length event]
  (let [[from to] (map fmt-participant [(:from event) (:to event)])
        lines     (note-lines event)
        color     (event-color event)]
    (str/join "\n"
              (remove nil?
                      [(format "\"%s\" -> \"%s\" %s: %s" from to color
                               (strip-invalid-xml-chars (label-fn event)))
                       (when (seq lines)
                         (format "note over \"%s\", \"%s\" %s: %s" from to color
                                 (fmt-note max-line-length lines)))]))))

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
      (str/replace "]" "~]")
      (str/replace "#" "~#")))

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
  "events need not be pre-sorted; sorted by :timestamp here. Each event's
   :from/:to (which dictate the arrow's direction) must already be set by
   the caller.

   opts: {:title           \"...\"                 diagram title
          :label-fn        (fn [event] \"...\")    arrow label, defaults to `default-label`
          :regions         [{:label \"...\" :start ms :end ms}]  wraps events whose
                            :timestamp falls in [:start :end] in `group :label ... end`
          :legend          [{:color \"#...\" :label \"...\"} ...]  legend rows;
                            each event's own :color styles its arrow/note
                            (falling back to a default gray when absent)
          :max-line-length n                       PlantUML's skinparam wrapWidth,
                            in pixels-per-character terms -- note/message text
                            wraps at word boundaries around n characters wide
                            (default 80)}"
  ([events] (events->plantuml events nil))
  ([events {:keys [title label-fn regions legend max-line-length]
            :or   {label-fn default-label legend []
                   max-line-length default-max-line-length}}]
   (let [events       (sort-by :timestamp events)
         participants (->> events (mapcat (juxt :from :to)) distinct (map fmt-participant))]
     (str/join "\n"
               (remove nil?
                       (concat
                         ["@startuml"]
                         [(str "skinparam wrapWidth " (* max-line-length px-per-char))]
                         (when title [(str "title " title)])
                         ["autonumber"]
                         (map #(format "participant \"%s\"" %) participants)
                         (grouped-lines regions events (map #(event->plantuml label-fn max-line-length %) events))
                         (when (seq (legend-lines legend))
                           (concat ["legend top left"] (legend-lines legend) ["endlegend"]))
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

(defn- open-file!
  "Opens `path` in the OS's default handler for its file type (e.g. a browser
   for an .svg), if the platform supports it."
  [path]
  (when (Desktop/isDesktopSupported)
    (.open (Desktop/getDesktop) (io/file path))))

(defn write-svg!
  "Renders events to an SVG at `path` (see events->plantuml for opts) and
   returns `path` resolved to an absolute path. :open? (default true) opens
   the file in the OS's default viewer after writing it."
  ([events path] (write-svg! events path nil))
  ([events path {:keys [open?] :or {open? true} :as opts}]
   (with-open [w (io/writer path)]
     (.write w (plantuml->svg (events->plantuml events opts))))
   (let [full-path (.getCanonicalPath (io/file path))]
     (when open? (open-file! full-path))
     full-path)))

(comment
  ;; Minimal: events already have :from/:to, no styling. :note renders as a
  ;; `note over` under the arrow when present.
  (def events
    [{:from :peer :to :dynamodb :timestamp 1 :tag "PutItem foo"
      :note {:Item {:id "foo" :value 42}}}
     {:from :dynamodb :to :peer :timestamp 2 :tag "200"}])
  (println (events->plantuml events))

  ;; A title, a custom arrow label, and grouping a run of events under a
  ;; `group ... end` block (as produced by setup's `region` macro).
  (println (events->plantuml events
                             {:title    "Demo"
                              :label-fn :tag
                              :regions  [{:label "warmup" :start 0 :end 2}]}))

  ;; Coloring/legend: each event carries its own :color; :legend is just the
  ;; rows to list underneath.
  (println (events->plantuml (map #(assoc % :color "#FFAEFB") events)
                             {:legend [{:color "#FFAEFB" :label "Storage (DynamoDB)"}]}))

  ;; Write straight to a .puml source file, or render straight to SVG --
  ;; both take the same opts as events->plantuml.
  (write-diagram! events "/tmp/events.puml")
  (write-svg! events "/tmp/events.svg")

  ;; :max-line-length shrinks skinparam wrapWidth *and* the threshold at
  ;; which break-long-words forces a hard break -- a raw binary blob's
  ;; escaped bytes have no whitespace for wrapWidth to wrap at on its own.
  (println (events->plantuml [{:from :peer :to :dynamodb :timestamp 1 :tag "Blob"
                               :note (apply str (repeat 200 "x"))}]
                             {:max-line-length 20}))

  ;; Adversarial payload: [ ] and # (creole link/numbered-list triggers),
  ;; plus a C0 control char () that's XML-illegal -- all handled
  ;; without throwing, and without corrupting the PlantUML/XML output.
  (println (events->plantuml [{:from :peer :to :dynamodb :timestamp 1 :tag "Weird"
                               :note {:payload (str "[link](x) #1 " (char 0x0B) " end")}}]))

  ;; The whole real pipeline lives in examples/datomic_caching.clj -- it
  ;; reads a tshark log, resolves :from/:to from ports itself, then calls
  ;; write-svg! with (optionally) setup's regions.
  )
