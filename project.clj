(defproject pal/pal-hashers "0.1.0-SNAPSHOT2"
  :description "A ClojureScript port of buddy-hashers"
  :url "https://github.com/leppert/pal-hashers"
  :license {:name "Apache License, Version 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.9.293"]
                 [com.cemerick/piggieback "0.2.1"]
                 [pal/pal-core "0.1.0-SNAPSHOT2"]]
  :plugins [[lein-cljsbuild "1.1.4"]
            [lein-npm       "0.6.2"]
            [lein-doo       "0.1.7"]]
  :npm {:dependencies [[source-map-support "0.4.6"]
                       [bcryptjs "leppert/bcrypt.js#02bfd95"]]}

  :source-paths ["src" "node_modules"]

  :doo {:build "test"
        :alias {:default [:node]}}

  :cljsbuild
  {:builds {:test {:source-paths ["src" "test"]
                   :compiler {:output-to     "target/pal-hashers-test/pal_hashers.js"
                              :output-dir    "target/pal-hashers-test"
                              :target        :nodejs
                              :language-in   :ecmascript5
                              :optimizations :none
                              :main          pal.test-runner}}}}

  :repl-options {:nrepl-middleware [cemerick.piggieback/wrap-cljs-repl]})
