(ns dynamodb
  (:require [http]
            [tshark :refer [decode-protocol]]
            [utils :refer [some-vals]]))

(defn- dynamo-operation
  "DynamoDB's operation name, e.g. \"PutItem\" -- the part of the
   X-Amz-Target header after the service prefix."
  [headers]
  (some->> (get headers "x-amz-target")
           (re-find #"\.(\S+)$")
           second))

(defn- dynamo-key [body]
  (some-> (or (get-in body [:Item :id])
              (get-in body [:Key :id]))
          first val))

(defn http->dynamodb [http-event]
  (let [{:keys [headers body status]} (:http http-event)
        operation (dynamo-operation headers)
        decoded   body
        k         (dynamo-key decoded)]
    (assoc http-event
      :dynamodb (some-vals
                  {:operation operation
                   :key       k
                   :status    status
                   :body      decoded}))))

(defmethod decode-protocol :dynamodb [_ record]
  (map http->dynamodb (decode-protocol :http record)))
