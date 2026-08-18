(ns diagram-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [clojure.java.io :as io]
            [diagram :refer [events->plantuml write-diagram!]]))

(deftest arrow-direction-and-color-test
  (testing "arrow points :from -> :to and carries the event's own :color"
    (let [puml (events->plantuml [{:from :peer :to :dynamodb :timestamp 1
                                    :tag "PutItem" :color "#ABCDEF"}])]
      (is (str/includes? puml "\"peer\" -> \"dynamodb\" #ABCDEF: PutItem"))))
  (testing "falls back to a default gray when :color is absent"
    (let [puml (events->plantuml [{:from :peer :to :dynamodb :timestamp 1 :tag "PutItem"}])]
      (is (str/includes? puml "#D3D3D3: PutItem")))))

(deftest regions-group-test
  (let [events      [{:from :a :to :b :timestamp 1 :tag "in-region"}
                      {:from :a :to :b :timestamp 10 :tag "outside"}]
        puml        (events->plantuml events {:regions [{:label "warmup" :start 0 :end 5}]})
        lines       (str/split-lines puml)
        idx-of      (fn [pred] (first (keep-indexed #(when (pred %2) %1) lines)))
        idxs-of     (fn [pred] (keep-indexed #(when (pred %2) %1) lines))
        group-start (idx-of #(str/starts-with? % "group warmup"))
        group-end   (first (filter #(> % group-start) (idxs-of #(= % "end"))))
        in-idx      (idx-of #(str/includes? % "in-region"))
        out-idx     (idx-of #(str/includes? % "outside"))]
    (is (some? group-start))
    (is (some? group-end))
    (is (< group-start in-idx group-end)
        "event inside the region's [:start :end] window is wrapped in the group")
    (is (> out-idx group-end)
        "event outside every region is emitted after the group closes, not wrapped in it")))

(deftest legend-test
  (let [puml (events->plantuml [{:from :a :to :b :timestamp 1 :tag "x"}]
                               {:legend [{:color "#FFAEFB" :label "Storage (DynamoDB)"}]})]
    (is (str/includes? puml "|<back:#FFAEFB>    </back>| Storage (DynamoDB) |"))))

(deftest escaping-test
  (testing "PlantUML-special chars and invalid XML control chars are neutralized, not thrown on"
    (let [bad-note {:payload (str "[link](x) #1 " (char 0x0B) " end")}
          puml     (events->plantuml [{:from :a :to :b :timestamp 1 :tag "x" :note bad-note}])]
      (is (str/includes? puml "~[link~](x) ~#1"))
      (is (not (str/includes? puml (str (char 0x0B))))
          "raw C0 control char must not survive into the rendered output")
      (is (not (re-find #"(?<!~)\[link" puml))
          "an un-escaped [ would be read by PlantUML's creole parser as a link"))))

(deftest long-word-wrap-test
  (let [word   (apply str (repeat 25 "a"))
        broken (#'diagram/break-long-word 10 word)]
    (is (str/includes? broken "\n") "a word longer than max-line-length must be forcibly split")
    (is (every? #(<= (count %) 10) (str/split broken #"\n"))
        "no resulting chunk may exceed max-line-length")
    (is (= word (str/replace broken "\n" "")) "splitting must not drop or alter any characters")))

(deftest status-only-response-test
  (testing "an event with no :note content renders inline, with no separate note block"
    (let [puml (events->plantuml [{:from :dynamodb :to :peer :timestamp 1 :tag "200"}])]
      (is (str/includes? puml "\"dynamodb\" -> \"peer\" #D3D3D3: 200"))
      (is (not (str/includes? puml "note over")))))
  (testing "an event with real :note content does get a separate note block"
    (let [puml (events->plantuml [{:from :dynamodb :to :peer :timestamp 1 :tag "200"
                                    :note {:Item {:id "foo"}}}])]
      (is (str/includes? puml "note over")))))

(deftest write-diagram-smoke-test
  (let [path (str (io/file (System/getProperty "java.io.tmpdir") "diagram-test.puml"))]
    (write-diagram! [{:from :a :to :b :timestamp 1 :tag "x"}] path)
    (is (pos? (.length (io/file path))))))
