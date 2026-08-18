(ns fressian-decode
  (:require [clojure.data.fressian :as fressian]
            [clojure.java.io])
  (:import (java.util List Set)
           (java.util.zip GZIPInputStream)
           (org.fressian TaggedObject)))

(defn- decode-tagged
  "Decodes one fressian TaggedObject's already-taggified values (`form`, the
   vector of its component values) into a tag-specific representation, per
   `readers` ({tag-string -> (fn [tag form] ...)}) -- e.g. reconstructing
   Datomic's parallel column arrays (index-tdata et al, see
   datomic-caching/datomic-index-readers) into row maps. A tag missing from
   `readers` unwraps a single-value form and wraps whatever's left in a
   plain tagged-literal, mirroring TaggedObject's own shape.

   `readers` is a plain map, not a multimethod, on purpose: this namespace
   has no business knowing Datomic's tag names, and a multimethod's global
   dispatch table would make different callers' (or tests') tag decodings
   stomp on each other."
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

(defn- gzip?
  "True if `b` starts with gzip's fixed 2-byte magic number (0x1f 0x8b) --
   Datomic gzips some memcache payloads but not others, so callers need to
   tell them apart before handing bytes to fressian."
  [^bytes b]
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
  ;; A real gzipped+fressian-encoded index-tdata payload, as captured off
  ;; the wire from a memcache GET response.
  (def byte-arr (byte-array [31 -117 8 0 0 0 0 0 0 -1 123 -1 -104 59 51 47 37 -75 66 -73 36 37 -79 36 -111 117 -85 -128 -120 -88 -104 -72 -124 -92 -108 -76 -123 -91 -107 -75 -115 -83 125 -128 -61 6 1 6 52 -80 89 -128 7 13 108 16 48 -125 2 11 48 8 112 8 112 -40 36 -16 21 13 -100 7 2 -96 -10 -100 -36 46 -107 67 0 127 77 -64 41 120 0 0 0]))

  (gzip? byte-arr) ; => true
  (gzip? (byte-array [0 1 2 3])) ; => false, no gzip magic bytes

  ;; taggify on its own, against an already-decoded fressian value (skips
  ;; the gunzip+fressian/read decode-body does) -- a TaggedObject nested
  ;; anywhere in maps/sets/lists/arrays gets swapped for a tagged-literal.
  (taggify {} {:nested [(org.fressian.TaggedObject. "my-tag" (object-array [[1 2 3]]))]})
  ; => {:nested [#my-tag [1 2 3]]}

  ;; Default decode (no readers): index-tdata's parallel column arrays come
  ;; back as a plain tagged-literal, columns un-zipped into rows.
  (decode-body byte-arr)
  ; => #index-tdata [[20 21 22 ...] [0 0 0 ...] [12 12 12 ...] [54 54 54 ...] [true true ...]]

  ;; With a readers map (the same shape datomic-caching/datomic-index-readers
  ;; passes in for real captures), index-tdata's columns are zipped into a
  ;; row per datom instead.
  (decode-body {"index-tdata"
                (fn [tag form]
                  (tagged-literal
                    (symbol tag)
                    (let [[v e a t added] form]
                      (mapv #(zipmap [:e :a :v :t :added] %&) e a v t added))))}
               byte-arr)
  ; => #index-tdata [{:e 20 :a 0 :v 12 :t 54 :added true} ...]

  )
