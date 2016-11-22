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
      :bcrypt+sha512
      :bcrypt+sha384)))

;; pal specific tests

(deftest pal-check-validates-buddy-hash
  (are [hash] (= true (hashers/check "foobar" hash))
    "bcrypt+sha512$0102030405060708090a0b0c0d0e0f10$12$e74c3d09fadf982b6a3d5d7a704134339ed6aac45f640500"
    "bcrypt+sha384$0102030405060708090a0b0c0d0e0f10$12$f56ffb6d2204d38ead28baedc7980ae0d86382713c14b68b"))
