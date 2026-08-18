(ns setup-test
  "setup.clj is almost entirely process orchestration (ProcessBuilder, ports,
  lsof, filesystem side effects) and isn't unit-testable without a live
  DynamoDB Local + memcached + transactor stack. The one genuinely pure,
  deterministic piece is the `region` macro's label-defaulting logic, tested
  below both via macroexpansion (no side effects) and via one careful
  runtime check that restores global state afterward."
  (:require [clojure.test :refer [deftest is testing]]
            [setup :as setup]))

(defn- expansion-label
  "Digs the :label value out of a `region` macroexpansion without caring
  about the rest of the generated let/swap! shape."
  [expanded-form]
  (->> (tree-seq coll? seq expanded-form)
       (filter map?)
       (some :label)))

(deftest region-label-defaulting-test
  (testing "single-form body: label defaults to that form's printed source"
    (is (= "(+ 1 2)"
           (expansion-label (macroexpand-1 '(setup/region (+ 1 2)))))))
  (testing "multi-form body: label defaults to the forms wrapped in `do`"
    (is (= "(do (println 1) (println 2))"
           (expansion-label (macroexpand-1 '(setup/region (println 1) (println 2)))))))
  (testing "explicit string first: overrides the default label"
    (is (= "explicit"
           (expansion-label (macroexpand-1 '(setup/region "explicit" (+ 1 2))))))))

(deftest region-runtime-test
  (testing "records one {:label :start :end} entry and returns body's value"
    (let [before (count @setup/regions)]
      (try
        (is (= 3 (setup/region (+ 1 2))))
        (is (= (inc before) (count @setup/regions)))
        (let [entry (peek @setup/regions)]
          (is (= "(+ 1 2)" (:label entry)))
          (is (<= (:start entry) (:end entry))))
        (finally
          ;; Restore global state -- `regions` is a shared defonce atom.
          (swap! setup/regions pop)))
      (is (= before (count @setup/regions))))))
