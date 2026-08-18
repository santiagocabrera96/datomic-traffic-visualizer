(ns fressian-decode
  (:require [clojure.data.fressian :as fressian]
            [clojure.java.io])
  (:import (java.util List Set)
           (java.util.zip GZIPInputStream)
           (org.fressian TaggedObject)))

(defn- decode-tagged
  "Decodes one fressian TaggedObject's already-taggified values (`form`, the
   vector of its component values) into a tag-specific representation, per
   `readers` ({tag-string -> (fn [tag form] ...)}). Give a tag richer
   structure than the default by adding an entry to `readers` (e.g.
   zip-columns below, reconstructing parallel column arrays into row maps);
   a tag missing from it unwraps a single-value form and wraps whatever's
   left in a plain tagged-literal, mirroring TaggedObject's own shape."
  [readers tag form]
  (if-let [reader (get readers tag)]
    (reader tag form)
    (tagged-literal (symbol tag) (if (= 1 (count form)) (first form) form))))

(defn- taggify
  "Recursively replace org.fressian.TaggedObject with clojure tagged literals
   (see decode-tagged), normalizing the java collections fressian hands back
   into clojure ones."
  [readers x]
  (cond
    (instance? TaggedObject x)
    (let [^TaggedObject t x]
      (decode-tagged readers (str (.getTag t)) (mapv (partial taggify readers) (.getValue t))))

    (record? x) (reduce-kv (fn [r k v] (assoc r k (taggify readers v))) x x)
    (map? x) (reduce-kv (fn [m k v] (assoc m (taggify readers k) (taggify readers v))) {} x)
    (instance? Set x) (into #{} (map (partial taggify readers)) x)
    (instance? List x) (mapv (partial taggify readers) x)
    (some-> x class .isArray) (mapv (partial taggify readers) x)
    :else x))

(defn- gzip? [^bytes b]
  (and (>= (alength b) 2)
       (= 0x1f (bit-and 0xff (aget b 0)))
       (= 0x8b (bit-and 0xff (aget b 1)))))

(defn decode-body
  "Decode one memcache value body: gunzip if needed, then fressian -> clojure.
   `readers` ({tag-string -> (fn [tag form] ...)}), if given, overrides how
   specific fressian tags are decoded -- see decode-tagged; a tag missing
   from it falls back to `(tagged-literal (symbol tag) form)`."
  ([b] (decode-body {} b))
  ([readers ^bytes b]
   (let [raw (if (gzip? b)
               (with-open [in (GZIPInputStream. (clojure.java.io/input-stream b))]
                 (.readAllBytes in))
               b)]
     (taggify readers (fressian/read raw)))))

(comment
  (def byte-arr (byte-array [31 -117 8 0 0 0 0 0 0 -1 123 -1 -104 59 51 47 37 -75 66 -73 36 37 -79 36 -111 117 -85 -128 -120 -88 -104 -72 -124 -92 -108 -76 -123 -91 -107 -75 -115 -83 125 -128 -61 6 1 6 52 -80 89 -128 7 13 108 16 48 -125 2 11 48 8 112 8 112 -40 36 -16 21 13 -100 7 2 -96 -10 -100 -36 46 -107 67 0 127 77 -64 41 120 0 0 0]))
  (decode-body byte-arr)
  (decode-body {"index-tdata"
                (fn [tag form]
                  (tagged-literal
                    (symbol tag)
                    (let [[v e a t added] form]
                      (mapv #(zipmap [:e :a :v :t :added] %&) e a v t added))))}
               byte-arr)

  ; Returns
  ;#index-tdata
  ;        [[20 21 22 23 24 25 26 27 56 57 58 59 60 61 63 64]
  ;         [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
  ;         [12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12]
  ;         [54 54 54 54 54 54 54 54 56 56 56 56 56 56 64 64]
  ;         [true true true true true true true true true true true true true true true true]]


  )
