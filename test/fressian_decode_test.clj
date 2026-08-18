(ns fressian-decode-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.data.fressian :as fressian]
            [fressian-decode :as fd])
  (:import (java.io ByteArrayOutputStream)
           (java.util.zip GZIPOutputStream)))

;; Test helpers -- write a fressian TaggedObject by hand (tag + N component
;; values), the same shape Datomic's own wire format uses and that
;; decode-tagged/taggify consume. clojure.data.fressian has no public
;; "write me a tagged value" helper, so we drive org.fressian.Writer's
;; writeTag/writeObject directly.
(defn- write-tagged-bytes ^bytes [tag components]
  (let [out (ByteArrayOutputStream.)
        w (fressian/create-writer out)]
    (.writeTag w tag (count components))
    (doseq [c components] (.writeObject w c))
    (.toByteArray out)))

(defn- gzip-bytes ^bytes [^bytes raw]
  (let [out (ByteArrayOutputStream.)]
    (with-open [gz (GZIPOutputStream. out)]
      (.write gz raw))
    (.toByteArray out)))

(deftest gzip?-detects-gzip-magic-bytes
  (testing "gzip magic bytes (0x1f 0x8b) are recognized regardless of what follows"
    (is (true? (#'fd/gzip? (byte-array [0x1f -0x75 0 0])))))
  (testing "non-gzip bytes are not misdetected"
    (is (false? (#'fd/gzip? (byte-array [0 1 2 3])))))
  (testing "too short to contain the magic bytes is not gzip"
    (is (false? (#'fd/gzip? (byte-array [0x1f]))))
    (is (false? (#'fd/gzip? (byte-array []))))))

(deftest decode-body-default-has-no-custom-readers
  (testing "plain (non-tagged) data round-trips untouched"
    (is (= {:a 1 :b [1 2 3]}
           (fd/decode-body (.array (fressian/write {:a 1 :b [1 2 3]}))))))
  (testing "a tagged value with no matching reader falls back to a tagged-literal,
            unwrapping its single component per decode-tagged's default"
    (is (= (tagged-literal 'some-tag [1 2 3])
           (fd/decode-body (write-tagged-bytes "some-tag" [[1 2 3]]))))))

(deftest decode-body-gunzips-when-gzip-magic-present
  (is (= {:a 1}
         (fd/decode-body (gzip-bytes (.array (fressian/write {:a 1})))))))

(deftest decode-body-custom-readers-invoke-matching-tag-only
  (let [readers {"index-tdata" (fn [tag form]
                                  (tagged-literal (symbol tag) (mapv #(zipmap [:e :v] %&) (first form) (second form)))
                                  )}
        bytes (write-tagged-bytes "index-tdata" [[1 2] ["a" "b"]])]
    (testing "a tag present in `readers` is decoded with the custom fn"
      (is (= (tagged-literal 'index-tdata [{:e 1 :v "a"} {:e 2 :v "b"}])
             (fd/decode-body readers bytes))))
    (testing "a tag absent from `readers` still falls back to the default decoding,
              unaffected by other entries in the map"
      (is (= (tagged-literal 'other-tag [1 2 3])
             (fd/decode-body readers (write-tagged-bytes "other-tag" [[1 2 3]])))))))

(deftest decode-body-empty-payload-throws
  (testing "an empty byte array is not gzip and has nothing for fressian to read --
            this is a malformed-input case the code is allowed to throw on, not handle"
    (is (thrown? java.io.EOFException (fd/decode-body (byte-array 0))))))
