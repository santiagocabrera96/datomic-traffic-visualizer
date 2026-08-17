(ns fressian-decode
  (:require [clojure.data.fressian]
            [clojure.java.io])
  (:import (java.util List Set)
           (java.util.zip GZIPInputStream)
           (org.fressian TaggedObject)))

(defmulti decode-tagged
  "Decodes one fressian TaggedObject's already-taggified values (`form`, the
   vector of its component values) into a tag-specific representation --
   dispatches on `tag` (the fressian tag string). Register a method here to
   give a specific tag richer structure than the default (e.g. zip-columns
   below, reconstructing parallel column arrays into row maps); the default
   unwraps a single-value form and wraps whatever's left in a plain
   tagged-literal, mirroring TaggedObject's own shape."
  (fn [tag _form] tag))

(defmethod fressian-decode/decode-tagged "index-tdata" [tag form]
  (tagged-literal
    (symbol tag)
    (let [[v e a t added] form]
      (mapv #(zipmap [:e :a :v :t :added]  %&) e a v t added))))

(defmethod fressian-decode/decode-tagged "index-dir-node" [tag form]
  (tagged-literal
    (symbol tag)
    (let [[index-tdata segment-id _ datom-count] form]
      (mapv #(zipmap [:first-datom :seg-id :datom-count] %&) (:form index-tdata) segment-id datom-count))))

(defmethod fressian-decode/decode-tagged "index-root-node" [tag form]
  (tagged-literal
    (symbol tag)
    (let [[index-tdata dir-id] form]
      (mapv #(zipmap [:first-datom :dir-id] %&) (:form index-tdata) dir-id))))

(defn- taggify
  "Recursively replace org.fressian.TaggedObject with clojure tagged literals
   (see decode-tagged), normalizing the java collections fressian hands back
   into clojure ones."
  [x]
  (cond
    (instance? TaggedObject x)
    (let [^TaggedObject t x]
      (decode-tagged (str (.getTag t)) (mapv taggify (.getValue t))))

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
