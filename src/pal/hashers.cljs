(ns pal.hashers
  (:refer-clojure :exclude [derive])
  (:require [cljs.nodejs :as nodejs]
            [clojure.string :as str]
            [pal.core.codecs :as codecs]
            [pal.core.hash :as hash]
            [pal.core.nonce :as nonce]
            [pal.core.bytes :as bytes]
            [goog.crypt :as gc]
            [goog.crypt.pbkdf2]
            [goog.string :as gstring]
            [goog.string.format]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:no-doc ^:static
  +iterations+
  {:pbkdf2+sha1 100000
   :bcrypt+sha512 12
   :bcrypt+sha384 12})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Impl Interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti parse-password
  "Parse password from string to parts."
  (fn [encryptedpassword]
    (-> encryptedpassword
        (str/split #"\$")
        (first)
        (keyword))))

(defn- dispatch
  [opts & args]
  (:alg opts))

(defmulti derive-password
  "Derive key depending on algorithm."
  dispatch)

(defmulti check-password
  "Password verification implementation."
  dispatch)

(defmulti format-password
  "Format password depending on algorithm."
  dispatch)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Derivation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod derive-password :pbkdf2+sha1
  [{:keys [alg password salt iterations]}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get +iterations+ alg))
        password (.deriveKeySha1 gc/pbkdf2 password salt iterations 160)]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

(defn- bcrypt-generate
  [password salt iterations]
  (.crypt (nodejs/require "bcryptjs") password salt iterations))

(defmethod derive-password :bcrypt+sha512
  [{:keys [alg password salt iterations]}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 16)))
        iterations (or iterations (get +iterations+ alg))
        password (-> (hash/sha512 password)
                     (bcrypt-generate salt iterations))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

(defmethod derive-password :bcrypt+sha384
  [{:keys [alg password salt iterations]}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 16)))
        iterations (or iterations (get +iterations+ alg))
        password (-> (hash/sha384 password)
                     (bcrypt-generate salt iterations))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod check-password :default
  [pwdparams attempt]
  (let [candidate (-> (assoc pwdparams :password attempt)
                      (derive-password))]
    (bytes/equals? (:password pwdparams)
                   (:password candidate))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Formatting
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod format-password :default
  [{:keys [alg password salt iterations]}]
  (let [algname (name alg)
        salt (codecs/bytes->hex salt)
        password (codecs/bytes->hex password)]
    (if (nil? iterations)
      (gstring/format "%s$%s$%s" algname salt password)
      (gstring/format "%s$%s$%s$%s" algname salt iterations password))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Parsing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod parse-password :default
  [encryptedpassword]
  (let [[alg salt iterations password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    {:alg alg
     :salt (codecs/hex->bytes salt)
     :password (codecs/hex->bytes password)
     :iterations (js/parseInt iterations)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn derive
  "Encrypts a raw string password."
  ([password] (derive password {}))
  ([password options]
   (-> (assoc options
              :alg (:alg options :bcrypt+sha512)
              :password (codecs/str->bytes password))
       (derive-password)
       (format-password))))

(defn check
  "Check if a unencrypted password matches
  with another encrypted password."
  ([attempt encrypted]
   (check attempt encrypted {}))
  ([attempt encrypted {:keys [limit setter prefered]}]
   (when (and attempt encrypted)
     (let [pwdparams (parse-password encrypted)]
       (if (and (set? limit) (not (contains? limit (:alg pwdparams))))
         false
         (let [attempt' (codecs/str->bytes attempt)
               result (check-password pwdparams attempt')]
           result))))))

(def encrypt
  "Backward compatibility alias for `derive`."
  derive)
