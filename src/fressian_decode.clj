(ns fressian-decode
  (:require [clojure.data.fressian]
            [clojure.java.io])
  (:import (java.util List Set)
           (java.util.zip GZIPInputStream)
           (org.fressian TaggedObject)))

(def ^:private tag-column-keys
  {"index-tdata"    [:v :e :a :t :added]
   "index-dir-node" [:first-datom :id :_ :datom-count]
   "index-root-node" [:first-datom :id]})

(defn- unwrap-col
  "A column may itself arrive as a tagged literal (e.g. a nested
   #index-data); the actual column values are its :form."
  [c]
  (if (tagged-literal? c) (:form c) c))

(defn- as-columns
  "Fressian sometimes hands the columns straight across as separate tag
   components (cs already has one seq per key), and sometimes wraps them all
   in a single nested collection. Normalize to a plain seq of column
   collections either way, unwrapping any individually tagged columns."
  [cs ks]
  (let [cs (mapv unwrap-col cs)]
    (if (or (= (count cs) (count ks)) (not= 1 (count cs)))
      cs
      (first cs))))

(assert
  (= (as-columns
       [(tagged-literal 'index-data [{:v 0, :e 0, :a 11, :t 54, :added true}]) [#uuid "6a77db06-93d3-42c4-a3b6-59f8aee851db"] [0] [123]]
       [:first-datom :id :unknown :datom-count])
     [[{:v 0, :e 0, :a 11, :t 54, :added true}] [#uuid "6a77db06-93d3-42c4-a3b6-59f8aee851db"] [0] [123]]))

(assert
  (= (as-columns
       [(tagged-literal 'index-data [{:v 0, :e 0, :a 11, :t 54, :added true}]) [#uuid "6a77db06-93d3-42c4-a3b6-59f8aee851db"] [0] [123]]
       [:first-datom :id :unknown :datom-count])
     [[{:v 0, :e 0, :a 11, :t 54, :added true}] [#uuid "6a77db06-93d3-42c4-a3b6-59f8aee851db"] [0] [123]]))

(defn- zip-columns
  "Zip a tag's parallel column arrays into an array of structs keyed by ks."
  [ks cs]
  (apply mapv #(zipmap ks %&) (as-columns cs ks)))

(defn- taggify
  "Recursively replace org.fressian.TaggedObject with clojure tagged literals,
   normalizing the java collections fressian hands back into clojure ones."
  [x]
  (cond
    (instance? TaggedObject x)
    (let [^TaggedObject t x
          tag (str (.getTag t))
          cs (mapv taggify (.getValue t))]
      (tagged-literal (symbol tag)
                      (if-let [ks (tag-column-keys tag)]
                        (zip-columns ks cs)
                        (if (= 1 (count cs)) (first cs) cs))))

    (record? x) (reduce-kv (fn [r k v] (assoc r k (taggify v))) x x)
    (map? x) (reduce-kv (fn [m k v] (assoc m (taggify k) (taggify v))) {} x)
    (instance? Set x) (into #{} (map taggify) x)
    (instance? List x) (mapv taggify x)
    (some-> x class .isArray) (mapv taggify x)
    :else x))

(defn- gzip? [^bytes b]
  (and (>= (alength b) 2)
       (= 0x1f (bit-and 0xff (aget b 0)))
       (= 0x8b (bit-and 0xff (aget b 1)))))

(defn fressian-body? [^bytes b]
  (and (pos? (alength b))
       (let [b0 (bit-and 0xff (aget b 0))]
         (or (= 0xfe b0)
             (and (> (alength b) 1) (= 0x1f b0) (= 0x8b (bit-and 0xff (aget b 1))))))))

(defn decode-body
  "Decode one memcache value body: gunzip if needed, then fressian -> clojure."
  [^bytes b]
  (let [raw (if (gzip? b)
              (with-open [in (GZIPInputStream. (clojure.java.io/input-stream b))]
                (.readAllBytes in))
              b)]
    (taggify (clojure.data.fressian/read raw))))

(comment
  (def byte-arr (byte-array [31 -117 8 0 0 0 0 0 0 -1 123 -1 -104 59 51 47 37 -75 66 -73 36 37 -79 36 -111 117 -85 -128 -120 -88 -104 -72 -124 -92 -108 -76 -123 -91 -107 -75 -115 -83 125 -128 -61 6 1 6 52 -80 89 -128 7 13 108 16 48 -125 2 11 48 8 112 8 112 -40 36 -16 21 13 -100 7 2 -96 -10 -100 -36 46 -107 67 0 127 77 -64 41 120 0 0 0]))
  (decode-body byte-arr)
  (fressian-body? byte-arr)

  ; Returns
  ;#index-tdata
  ;        [[20 21 22 23 24 25 26 27 56 57 58 59 60 61 63 64]
  ;         [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
  ;         [12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12]
  ;         [54 54 54 54 54 54 54 54 56 56 56 56 56 56 64 64]
  ;         [true true true true true true true true true true true true true true true true]]


  )
