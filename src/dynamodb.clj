(ns dynamodb
  "Requires http (to get already-decoded :http events to enrich) and tshark
   (to register against its decode-protocol multimethod) -- see tshark's
   docstring for how self-registering protocol namespaces work."
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

(defn- dynamo-key
  "The entity id out of a request body. Requests carry it under :Item
   (PutItem) or :Key (GetItem/UpdateItem/DeleteItem); either way the value
   is a single-key AttributeValue map, e.g. {:S \"abc\"} -- (first val)
   pulls out just \"abc\", dropping the S/N/... type tag."
  [body]
  (some-> (or (get-in body [:Item :id])
              (get-in body [:Key :id]))
          first val))

(defn http->dynamodb [http-event]
  (let [{:keys [headers body status]} (:http http-event)
        operation (dynamo-operation headers)
        k         (dynamo-key body)]
    (assoc http-event
      :dynamodb (some-vals
                  {:operation operation
                   :key       k
                   :status    status
                   :body      body}))))

(defmethod decode-protocol :dynamodb [_ record]
  (map http->dynamodb (decode-protocol :http record)))

(comment
  ;; PutItem request: operation from X-Amz-Target, key from :Item
  (http->dynamodb
    {:http {:headers {"x-amz-target" "DynamoDB_20120810.PutItem"}
            :body    {:TableName "orders"
                      :Item      {:id     {:S "order-42"}
                                  :status {:S "pending"}}}}})
  ;; => {:http {...} :dynamodb {:operation "PutItem" :key "order-42" :body {...}}}

  ;; GetItem request: key from :Key instead of :Item
  (http->dynamodb
    {:http {:headers {"x-amz-target" "DynamoDB_20120810.GetItem"}
            :body    {:TableName "orders" :Key {:id {:S "order-42"}}}}})

  ;; response: no X-Amz-Target header, no body -- :operation/:key/:body
  ;; are all dropped by some-vals, leaving just :status
  (http->dynamodb {:http {:headers {} :status 200}}))
