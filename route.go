package main

import (
	"errors"
	"fmt"
	"github.com/duo-labs/webauthn/models"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	"github.com/nimblehq/webauthn-growth-demo/api"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	b64 "encoding/base64"
	res "github.com/nimblehq/webauthn-growth-demo/response"
)

var store = sessions.NewCookieStore([]byte("duo-rox"))

func Login(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", nil)
}

func Index(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]

	if username == "" {
		fmt.Println("Getting default user for dashboard")
		username = "testuser@example.com"
	}

	user, err := models.GetUserByUsername(username + "@example.com")

	if err != nil {
		fmt.Println("Error retreiving user for dashboard: ", err)
		api.JSONResponse(w, "Error retreiving user", http.StatusInternalServerError)
		return
	}

	type TemplateData struct {
		User        string
		Credentials []res.FormattedCredential
	}

	creds, err := models.GetCredentialsForUser(&user)
	fcs, err := res.FormatCredentials(creds)

	td := TemplateData{
		User:        user.DisplayName,
		Credentials: fcs,
	}

	renderTemplate(w, "index.html", td)
}

// RequestNewCredential begins Credential Registration Request when /MakeNewCredential gets hit
func RequestNewCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]

	attType := r.FormValue("attType")
	authType := r.FormValue("authType")
	timeout := 60000
	// Get Registrant User

	user, err := models.GetUserByUsername(username)
	if err != nil {
		user = models.User{
			DisplayName: strings.Split(username, "@")[0],
			Name:        username,
		}
		err = models.PutUser(&user)
		if err != nil {
			api.JSONResponse(w, "Error creating new user", http.StatusInternalServerError)
			return
		}
	}

	params := []res.CredentialParameter{
		res.CredentialParameter{
			Type:      "public-key",
			Algorithm: "-7",
		},
		res.CredentialParameter{
			Type:      "public-key",
			Algorithm: "-257", // RS256 for Windows Hello
		},
	}

	// Get the proper URL the request is coming from
	u, err := url.Parse(r.Referer())

	// Get Relying Party that is requesting Registration
	rp, err := models.GetRelyingPartyByHost(u.Hostname())

	if err == gorm.ErrRecordNotFound {
		fmt.Println("No RP found for host ", u.Hostname())
		fmt.Printf("Request: %+v\n", r)
		api.JSONResponse(w, "No relying party defined", http.StatusInternalServerError)
		return
	}

	// Log this Registration session
	sd, err := models.CreateNewSession(&user, &rp, "reg")
	if err != nil {
		fmt.Println("Something went wrong creating session data:", err)
		api.JSONResponse(w, "Session Data Creation Error", http.StatusInternalServerError)
		return
	}

	// Give us a safe (looking) way to manage the session btwn us and the client
	session, _ := store.Get(r, "registration-session")
	session.Values["session_id"] = sd.ID
	session.Save(r, w)

	makeOptRP := res.MakeOptionRelyingParty{
		Name: rp.DisplayName,
		ID:   rp.ID,
	}

	makeOptUser := res.MakeOptionUser{
		Name:        user.Name,
		DisplayName: user.DisplayName,
		ID:          user.ID,
	}

	authSelector := res.AuthenticatorSelection{
		AuthenticatorAttachment: authType,
		RequireResidentKey:      false,
		UserVerification:        "preferred",
	}

	makeResponse := res.MakeCredentialResponse{
		Challenge:              sd.Challenge,
		RP:                     makeOptRP,
		User:                   makeOptUser,
		Parameters:             params,
		Timeout:                timeout,
		AuthenticatorSelection: authSelector,
		AttestationType:        attType,
		Extensions:             res.Extensions{true},
	}

	api.JSONResponse(w, makeResponse, http.StatusOK)
}

// MakeNewCredential - Attempt to make a new credential given an authenticator's response
func MakeNewCredential(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}

	encodedAuthData, err := api.DecodeAttestationObject(r.PostFormValue("attObj"))
	decodedAuthData, err := api.ParseAuthData(encodedAuthData)

	if err != nil {
		api.JSONResponse(w, "Error parsing the authentication data", http.StatusNotFound)
		return
	}

	clientData, err := api.UnmarshallClientData(r.PostFormValue("clientData"))
	if err != nil {
		api.JSONResponse(w, "Error getting client data", http.StatusNotFound)
		return
	}

	session, err := store.Get(r, "registration-session")
	if err != nil {
		fmt.Println("Error getting session data", err)
		api.JSONResponse(w, "Error getting session data", http.StatusNotFound)
		return
	}

	sessionID := session.Values["session_id"].(uint)
	sessionData, err := models.GetSessionData(sessionID)

	verified, err := api.VerifyRegistrationData(&clientData, &decodedAuthData, &sessionData)

	if err != nil {
		fmt.Println("Error verifying credential", err)
		api.JSONResponse(w, "Error verifying credential", http.StatusBadRequest)
		return
	}

	if verified {
		newCredential := models.Credential{
			Counter:        decodedAuthData.Counter,
			RelyingPartyID: sessionData.RelyingPartyID,
			RelyingParty:   sessionData.RelyingParty,
			UserID:         sessionData.UserID,
			User:           sessionData.User,
			Format:         decodedAuthData.Format,
			Type:           r.PostFormValue("type"),
			Flags:          decodedAuthData.Flags,
			CredID:         r.PostFormValue("id"),
			PublicKey:      decodedAuthData.PubKey,
		}
		err := models.CreateCredential(&newCredential)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%+v\n", newCredential)
		api.JSONResponse(w, res.CredentialActionResponse{
			Success:    true,
			Credential: newCredential,
		}, http.StatusOK)
	} else {
		api.JSONResponse(w, res.CredentialActionResponse{
			Success:    false,
			Credential: models.Credential{},
		}, http.StatusOK)
	}
}

// GetAssertion - assemble the data we need to make an assertion against
// a given user and authenticator
func GetAssertion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	timeout := 60000

	u, err := url.Parse(r.Referer())

	user, rp, err := GetUserAndRelyingParty(username, u.Hostname())
	if err != nil {
		fmt.Println("Couldn't Find the User or RP, most likely the User:", err)
		api.JSONResponse(w, "Couldn't Find User", http.StatusInternalServerError)
		return
	}

	sd, err := models.CreateNewSession(&user, &rp, "att")
	if err != nil {
		fmt.Println("Something went wrong creating session data:", err)
		api.JSONResponse(w, "Session Data Creation Error", http.StatusInternalServerError)
		return
	}

	creds, err := models.GetCredentialsForUserAndRelyingParty(&user, &rp)
	if err != nil {
		fmt.Println("No Credential Record Found:", err)
		api.JSONResponse(w, "Session Data Creation Error", http.StatusNotFound)
		return
	}

	session, _ := store.Get(r, "assertion-session")
	session.Values["session_id"] = sd.ID
	session.Save(r, w)

	type AllowedCredential struct {
		CredID     string   `json:"id"`
		Type       string   `json:"type"`
		Transports []string `json:"transports"`
	}

	type PublicKeyCredentialOptions struct {
		Challenge []byte              `json:"challenge,omitempty"`
		Timeout   int                 `json:"timeout,omitempty"`
		AllowList []AllowedCredential `json:"allowCredentials,omitempty"`
		RPID      string              `json:"rpId,omitempty"`
	}

	if err != nil {
		fmt.Println("Error Decoding Credential ID:", err)
		api.JSONResponse(w, "Error Decoding Credential ID", http.StatusNotFound)
		return
	}

	var acs []AllowedCredential

	for _, cred := range creds {
		ac := AllowedCredential{
			CredID:     cred.CredID,
			Type:       "public-key", // This should always be type 'public-key' for now
			Transports: []string{"usb", "nfc", "ble"},
		}
		acs = append(acs, ac)
	}

	assertionResponse := PublicKeyCredentialOptions{
		Challenge: sd.Challenge,
		Timeout:   timeout,
		AllowList: acs,
		RPID:      rp.ID,
	}

	api.JSONResponse(w, assertionResponse, http.StatusOK)
}

// GetUserAndRelyingParty - Get the relevant user and rp for a given WebAuthn ceremony
func GetUserAndRelyingParty(username string, hostname string) (models.User, models.RelyingParty, error) {
	// Get Registering User
	user, err := models.GetUserByUsername(username)

	if err == gorm.ErrRecordNotFound {
		fmt.Println("No user record found with username ", username)
		err = errors.New("No User found")
		return user, models.RelyingParty{}, err
	}

	// Get Relying Party that is requesting Registration
	rp, err := models.GetRelyingPartyByHost(hostname)

	if err == gorm.ErrRecordNotFound {
		err = errors.New("No RP found")
		return user, rp, err
	}

	return user, rp, nil
}

// MakeAssertion - Validate the Assertion Data provided by the authenticator and
// resond whether or not it was successful alongside the relevant credential.
func MakeAssertion(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "assertion-session")
	sessionID := session.Values["session_id"].(uint)
	sessionData, err := models.GetSessionData(sessionID)
	if err != nil {
		api.JSONResponse(w, "Missing Session Data Cookie", http.StatusBadRequest)
		return
	}

	encoder := b64.URLEncoding.Strict()
	encAssertionData, err := encoder.DecodeString(r.PostFormValue("authData"))
	if err != nil {
		fmt.Println("b64 Decode Error: ", err)
		api.JSONResponse(w, "Error decoding assertion data", http.StatusBadRequest)
		return
	}

	authData, err := api.ParseAssertionData(encAssertionData, r.PostFormValue("signature"))

	if err != nil {
		fmt.Println("Parse Assertion Error: ", err)
		api.JSONResponse(w, "Error parsing assertion data", http.StatusBadRequest)
		return
	}

	clientData, err := api.UnmarshallClientData(r.PostFormValue("clientData"))

	var credentialID string
	credentialID = r.FormValue("id")

	if credentialID == "" {
		api.JSONResponse(w, "Missing Credential ID", http.StatusBadRequest)
		return
	}

	verified, credential, _ := api.VerifyAssertionData(&clientData, &authData, &sessionData, credentialID)

	api.JSONResponse(w, res.CredentialActionResponse{
		Success:    verified,
		Credential: credential,
	}, http.StatusOK)
}

// CreateNewUser - hitting this endpoint with a new user will add it to the db
func CreateNewUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	icon := "example.icon.duo.com/123/avatar.png"
	if username == "" {
		api.JSONResponse(w, "username", http.StatusBadRequest)
		return
	}
	if email == "" {
		api.JSONResponse(w, "email", http.StatusBadRequest)
		return
	}

	u := models.User{
		Name:        email,
		DisplayName: username,
		Icon:        icon,
	}

	user, err := models.GetUserByUsername(u.Name)
	if err != gorm.ErrRecordNotFound {
		fmt.Println("Got user " + user.Name)
		api.JSONResponse(w, user, http.StatusOK)
		return
	}

	err = models.PutUser(&u)
	if err != nil {
		api.JSONResponse(w, "Error Creating User", http.StatusInternalServerError)
		return
	}

	api.JSONResponse(w, u, http.StatusCreated)
}

// GetUser - get a user from the db
func GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	u, err := models.GetUserByUsername(username)
	if err != nil {
		fmt.Println(err)
		api.JSONResponse(w, "User not found, try registering one first!", http.StatusNotFound)
		return
	}
	api.JSONResponse(w, u, http.StatusOK)
}

// GetCredentials - get a user's credentials from the db
func GetCredentials(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	u, _ := models.GetUserByUsername(username)
	cs, err := models.GetCredentialsForUser(&u)
	if err != nil {
		fmt.Println(err)
		api.JSONResponse(w, "", http.StatusNotFound)
	} else {
		api.JSONResponse(w, cs, http.StatusOK)
	}
}

// DeleteCredential - Delete a credential from the db
func DeleteCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	credID := vars["id"]
	err := models.DeleteCredentialByID(credID)
	fmt.Println("Deleting credential with ID ", credID)
	if err != nil {
		fmt.Println(err)
		api.JSONResponse(w, "Credential not Found", http.StatusNotFound)
	} else {
		api.JSONResponse(w, "Success", http.StatusOK)
	}
}

// CheckCredentialCounter - We may want to check for replay attacks but
// we definitely want to update the internal counter
// Note: this currently doesn't do that, lol
func CheckCredentialCounter(cred *models.Credential) error {
	return models.UpdateCredential(cred)
}

// renderTemplate renders the template to the ResponseWriter
func renderTemplate(w http.ResponseWriter, f string, data interface{}) {
	t, err := template.ParseFiles(fmt.Sprintf("./templates/%s", f))
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}
