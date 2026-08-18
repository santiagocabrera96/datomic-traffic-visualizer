(ns utils-test
  (:require [clojure.test :refer [deftest is testing]]
            [utils :refer [->vec some-vals hex-payload->bytes
                            update-in-if-present unpack-7bit-lsb]]))

(deftest ->vec-nil-becomes-empty-vector
  (is (= [] (->vec nil))))

(deftest ->vec-passes-through-any-sequential-collection
  (testing "vector"
    (is (= [1 2] (->vec [1 2]))))
  (testing "list"
    (is (= [1 2] (->vec '(1 2))))))

(deftest ->vec-wraps-a-non-sequential-value-eg-a-lone-map
  ;; this is the whole point of ->vec: tshark's JSON gives back a bare map
  ;; when a repeated field occurs once, instead of a one-element vector.
  (is (= [{:a 1}] (->vec {:a 1}))))

(deftest some-vals-drops-nil-valued-entries-only
  (is (= {:a 1 :c 2} (some-vals {:a 1 :b nil :c 2}))))

(deftest some-vals-of-empty-map-is-empty-map
  (is (= {} (some-vals {}))))

(deftest some-vals-drops-a-falsey-but-non-nil-value
  ;; false is a valid value and must survive -- only nil is dropped
  (is (= {:a false} (some-vals {:a false :b nil}))))

(deftest hex-payload->bytes-parses-colon-separated-hex
  (is (= [120 86 52 18] (hex-payload->bytes "78:56:34:12"))))

(deftest hex-payload->bytes-of-blank-or-nil-input-is-nil
  (is (nil? (hex-payload->bytes "")))
  (is (nil? (hex-payload->bytes nil))))

(deftest update-in-if-present-updates-an-existing-path
  (is (= {:a {:b 2}} (update-in-if-present {:a {:b 1}} [:a :b] inc))))

(deftest update-in-if-present-is-a-no-op-when-path-is-missing
  ;; unlike clojure.core/update-in, this must NOT create {:a {:b ...}}
  ;; out of thin air when :b was never there.
  (is (= {:a {}} (update-in-if-present {:a {}} [:a :b] inc)))
  (is (= {} (update-in-if-present {} [:a :b] inc))))

(deftest update-in-if-present-treats-an-explicit-nil-value-as-present
  ;; a key whose value is nil is still "present" -- f runs on nil
  (is (= {:a {:b 1}} (update-in-if-present {:a {:b nil}} [:a :b] (constantly 1)))))

(deftest unpack-7bit-lsb-of-empty-string-is-empty
  (is (= 0 (count (unpack-7bit-lsb "")))))

(deftest unpack-7bit-lsb-of-a-single-char-yields-no-complete-byte
  ;; 7 bits isn't enough for a full byte -- the leftover bits are dropped,
  ;; not padded out, so a lone char always decodes to zero bytes.
  (is (= 0 (count (unpack-7bit-lsb (str (char 65)))))))

(deftest unpack-7bit-lsb-packs-bits-across-a-char-boundary
  ;; two DEL (127 = 0b1111111) chars supply 14 bits; only the first 8
  ;; become a full output byte (0xFF), the remaining 6 bits are truncated.
  (is (= [-1] (vec (unpack-7bit-lsb (str (char 127) (char 127)))))))

(deftest unpack-7bit-lsb-round-trips-a-known-packing-of-Hi
  ;; codepoints 72,82,1 are "Hi" (bytes 72 105) packed 7-bit-LSB by hand
  (is (= [72 105] (vec (unpack-7bit-lsb (str (char 72) (char 82) (char 1)))))))
