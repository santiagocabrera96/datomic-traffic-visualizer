(ns dynamodb-test
  (:require [clojure.test :refer [deftest is testing]]
            [dynamodb :refer [http->dynamodb]]))

(deftest operation-from-x-amz-target
  (testing "operation name is the part of X-Amz-Target after the service prefix"
    (let [event (http->dynamodb
                  {:http {:headers {"x-amz-target" "DynamoDB_20120810.PutItem"}
                          :body    {:Item {:id {:S "abc"}}}}})]
      (is (= "PutItem" (get-in event [:dynamodb :operation]))))))

(deftest key-from-item
  (testing "PutItem-shaped body: key comes from :Item"
    (let [event (http->dynamodb
                  {:http {:headers {"x-amz-target" "DynamoDB_20120810.PutItem"}
                          :body    {:Item {:id {:S "abc"}}}}})]
      (is (= "abc" (get-in event [:dynamodb :key]))))))

(deftest key-from-key
  (testing "GetItem-shaped body: key comes from :Key when :Item is absent"
    (let [event (http->dynamodb
                  {:http {:headers {"x-amz-target" "DynamoDB_20120810.GetItem"}
                          :body    {:Key {:id {:N "42"}}}}})]
      (is (= "42" (get-in event [:dynamodb :key]))))))

(deftest response-event-has-no-operation-or-key
  (testing "a response has no X-Amz-Target and no body -- those keys are
            dropped entirely rather than present with nil values"
    (let [event (http->dynamodb {:http {:headers {} :status 200}})]
      (is (= {:status 200} (:dynamodb event)))
      (is (not (contains? (:dynamodb event) :operation)))
      (is (not (contains? (:dynamodb event) :key))))))

(deftest missing-x-amz-target-header-does-not-throw
  (testing "no headers at all is a valid input, not an error"
    (let [event (http->dynamodb {:http {:body {:Item {:id {:S "abc"}}}}})]
      (is (not (contains? (:dynamodb event) :operation)))
      (is (= "abc" (get-in event [:dynamodb :key]))))))
