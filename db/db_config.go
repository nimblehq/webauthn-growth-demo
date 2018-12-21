package db

import (
	"github.com/duo-labs/webauthn/models"
	"github.com/nanobox-io/golang-scribble"
)

var DB *scribble.Driver

const dbColletion = "users"

type (
	dbDevice struct {
		Name         string `json:"name"`
		Origin       string `json:"origin"`
		Challenge    []byte `json:"challenge"`
		CredentialID string `json:"credentialId"`
	}

	dbItem struct {
		User    models.User          `json:"user"`
		Devices map[string]*dbDevice `json:"devices"`
	}
)

func InitDatabase() {
	var err error
	DB, err = scribble.New("data", &scribble.Options{})
	if err != nil {
		panic(err)
	}
}
