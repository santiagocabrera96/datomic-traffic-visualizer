(ns utils
  (:require [clojure.string :as str]))

(defn ->vec
  "Normalizes tshark's JSON quirk where a repeated field comes back as a
   bare map when there's exactly one, but a vector of maps when there's
   more than one -- nil becomes [], an already-sequential x is just
   vec'd, anything else (e.g. a lone map) is wrapped in a single-element
   vector."
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

(defn update-in-if-present
  "Like update-in, but a no-op when ks isn't present in m -- plain
   update-in would call (f nil) and graft a new nested path into m even
   when the key never existed."
  [m ks f]
  (if (not= ::missing (get-in m ks ::missing))
    (update-in m ks f)
    m))

(defn unpack-7bit-lsb
  "Undoes Datomic/DynamoDB's 7-bit-LSB byte packing: bytes are packed 7
   bits at a time, least-significant-bit first, with no padding between
   characters, so the whole string stays codepoint 0-127 (safe to store
   as a DynamoDB string). Because 7 doesn't divide 8, a source byte's
   bits can span two packed characters, and the tail end of the bitstream
   may hold fewer than 8 leftover bits -- those are dropped rather than
   padded out to a partial byte, so n characters always decode to
   exactly (quot (* 7 n) 8) bytes."
  [^String s]
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

(comment
  (->vec nil)             ;=> []
  (->vec [1 2])           ;=> [1 2], already sequential
  (->vec '(1 2))          ;=> [1 2], any sequential, not just vectors
  (->vec {:a 1})          ;=> [{:a 1}], a lone map is the "one repeat" case
  (->vec 5)               ;=> [5]

  (some-vals {:a 1 :b nil :c 2})  ;=> {:a 1 :c 2}
  (some-vals {})                  ;=> {}
  (some-vals {:a nil})            ;=> {}

  (hex-payload->bytes "78:56:34:12") ;=> [120 86 52 18]
  (hex-payload->bytes "")            ;=> nil
  (hex-payload->bytes nil)           ;=> nil

  (update-in-if-present {:a {:b 1}} [:a :b] inc)  ;=> {:a {:b 2}}
  (update-in-if-present {:a {}} [:a :b] inc)      ;=> {:a {}}, untouched
  (update-in-if-present {} [:a :b] inc)           ;=> {}, untouched

  ;; a single 7-bit char can't hold a full byte -- decodes to nothing
  (unpack-7bit-lsb (str (char 65)))                    ;=> []
  ;; two DEL (codepoint 127) chars pack 14 bits -> 1 full byte, all set
  (vec (unpack-7bit-lsb (str (char 127) (char 127))))  ;=> [-1]
  ;; codepoints 72,82,1 are the real 7-bit-LSB packing of "Hi" (bytes 72 105)
  (vec (unpack-7bit-lsb (str (char 72) (char 82) (char 1)))))  ;=> [72 105]
