package main

import (
	"github.com/gorilla/mux"
	"github.com/nimblehq/webauthn-growth-demo/db"
	log "github.com/sirupsen/logrus"

	"net/http"
)

func main() {
	db.InitDatabase()

	muxRouter := newRouter()
	port := ":8080"
	log.WithFields(log.Fields{"port": port}).Info("Listening at port")

	err := http.ListenAndServe(port, muxRouter)
	if err != nil {
		panic(err)
	}
}

func newRouter() *mux.Router {
	router := mux.NewRouter()

	// Add new handlers here
	router.HandleFunc("/", Login)
	router.HandleFunc("/dashboard/{name}", Index)
	router.HandleFunc("/dashboard", Index)
	router.HandleFunc("/makeCredential/{name}", RequestNewCredential).Methods("GET")
	router.HandleFunc("/makeCredential", MakeNewCredential).Methods("POST")
	router.HandleFunc("/assertion/{name}", GetAssertion).Methods("GET")
	router.HandleFunc("/assertion", MakeAssertion).Methods("POST")
	router.HandleFunc("/user", CreateNewUser).Methods("POST")
	router.HandleFunc("/user/{name}", GetUser).Methods("GET")
	router.HandleFunc("/credential/{name}", GetCredentials).Methods("GET")
	router.HandleFunc("/credential/{id}", DeleteCredential).Methods("DELETE")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	return router
}
