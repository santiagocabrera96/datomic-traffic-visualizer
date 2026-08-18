(ns utils
  (:require [clojure.string :as str]))

(defn ->vec
  [x]
  (cond (nil? x) [] (sequential? x) (vec x) :else [x]))

(defn some-vals
  "m with nil-valued entries dropped -- an event map shouldn't carry keys
   that don't apply to it (e.g. :status on a request)."
  [m]
  (into (empty m) (remove (comp nil? val)) m))

(defn hex-payload->bytes
  "tshark's colon-hex payload string (e.g. \"78:56:34:12\") as a vector of
   byte values (0-255) instead."
  [hex]
  (when (seq hex)
    (mapv #(Integer/parseInt % 16) (str/split hex #":"))))

(defn update-in-if-present [m ks f]
  (if (not= ::missing (get-in m ks ::missing))
    (update-in m ks f)
    m))

(defn unpack-7bit-lsb [^String s]
  (let [n (count s)
        nbytes (quot (* 7 n) 8)
        out (byte-array nbytes)]
    (dotimes [i n]
      (let [c (long (.charAt s i)) bit-pos (* 7 i)]
        (dotimes [b 7]
          (when (bit-test c b)
            (let [pos (+ bit-pos b) byte-idx (quot pos 8) bit-in-byte (rem pos 8)]
              (when (< byte-idx nbytes)
                (aset out byte-idx (unchecked-byte (bit-or (bit-and 0xff (aget out byte-idx))
                                                           (bit-shift-left 1 bit-in-byte))))))))))
    out))

; TODO: Create rich comment block of the code here.