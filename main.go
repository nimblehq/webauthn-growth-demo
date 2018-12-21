package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nimblehq/webauthn-growth-demo/handlers"
	log "github.com/sirupsen/logrus"
)

func main() {
	muxRouter := newRouter()
	port := ":8080"
	log.WithFields(log.Fields{"port": port}).Info("Listening at port")

	err := http.ListenAndServe(port, muxRouter)
	if err != nil {
		panic(err)
	}
}

func newRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", handler).Methods("GET")

	staticFileDirectory := http.Dir("./assets/")
	staticFileHandler := http.StripPrefix("/users/", http.FileServer(staticFileDirectory))
	r.PathPrefix("/users/").Handler(staticFileHandler).Methods("GET")

	r.HandleFunc("/users", handlers.GetUsersHandler).Methods("GET")
	r.HandleFunc("/users", handlers.CreateUsersHandler).Methods("POST")
	return r
}

func handler(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprint(w, "Hello World!")
	if err != nil {
		log.Fatal(err)
	}
}
