(ns pal.hashers.test-runner
 (:require [doo.runner :refer-macros [doo-tests]]
           [pal.hashers-test]
           [cljs.nodejs :as nodejs]))

(try
  (.install (nodejs/require "source-map-support"))
  (catch :default _))

(doo-tests
 'pal.hashers-test)
