(ns pal.hashers-test
  (:require [cljs.test :refer-macros [deftest testing is are]]
            [pal.hashers :as hashers]
            [pal.core.nonce :as nonce]
            [pal.core.codecs :refer [bytes->hex]]))

;; tests copied from buddy

(deftest pal-hashers
  (let [pwd "my-test-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:alg alg})]
          (hashers/check pwd result))
      :bcrypt+sha512)))

(deftest confirm-check-failure
  (let [pwd-good "my-test-password"
        pwd-bad "my-text-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd-good {:alg alg})]
          (not (hashers/check pwd-bad result)))
      :bcrypt+sha512)))

(deftest buddy-hashers-nil
  (let [pwd "my-test-password"
        result (hashers/encrypt pwd {:alg :bcrypt+sha512})]
    (is (nil? (hashers/check nil result)))
    (is (nil? (hashers/check pwd nil)))
    (is (nil? (hashers/check nil nil)))))

(deftest algorithm-embedded-in-hash
  (let [pwd "my-test-password"]
    (are [alg]
        (-> (hashers/encrypt pwd {:alg alg})
            (.startsWith (name alg)))
      :bcrypt+sha512)))

;; Confirm that the algorithm used is always embedded at the
;; start of the hash, and that the salt is also appended (after
;; being converted to their byte values)

(deftest received-salt-embedded-in-hash
  (let [pwd "my-test-password"
        salt (nonce/random-bytes 16)]
    (are [alg]
        (-> (hashers/encrypt pwd {:alg alg :salt salt})
            (.startsWith (str (name alg) "$" (bytes->hex salt))))
      :bcrypt+sha512)))

(deftest limit-available-algorithms
  (let [pwd (hashers/encrypt "hello" {:alg :bcrypt+sha512})
        limit #{:pbkdf2+sha256 :scrypt}]
    (is (hashers/check "hello" pwd))
    (is (not (hashers/check "hello" pwd {:limit limit})))))

(deftest debug-time-bench
  (let [pwd "my-test-password"]
    (are [alg]
        (do
          (println alg)
          (time (hashers/encrypt pwd {:alg alg}))
          true)
      :bcrypt+sha512)))

;; pal specific tests

(def buddy-hash-bcrypt+sha512
  "bcrypt+sha512$746869732d69732d612d73616c742d6b$12$5581af5775b6cd414ac23691a9e85e7b912b1f4f1bf7ecc4")

(deftest pal-derive-matches-buddy-derive
  (let [opts (-> buddy-hash-bcrypt+sha512
                 hashers/parse-password
                 (dissoc :password))
        pal-hash (hashers/derive "foobar" opts)]
    (is (= buddy-hash-bcrypt+sha512 pal-hash))))

(deftest pal-check-validates-buddy-hash
    (is (hashers/check "foobar" buddy-hash-bcrypt+sha512)))
