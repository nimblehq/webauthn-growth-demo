package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Description string `json:"description"`
}

var users []User

func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	//Convert the "users" variable to json
	usersListBytes, err := json.Marshal(users)

	// If there is an error, print it to the console, and return a server
	// error response to the user
	if err != nil {
		fmt.Println(fmt.Errorf("Error: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// If all goes well, write the JSON list of users to the response
	w.Write(usersListBytes)
}

func CreateUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new instance of User
	user := User{}

	// We send all our data as HTML form data
	// the `ParseForm` method of the request, parses the
	// form values
	err := r.ParseForm()

	// In case of any error, we respond with an error to the user
	if err != nil {
		fmt.Println(fmt.Errorf("Error: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Get the information about the user from the form info
	user.FirstName = r.Form.Get("first_name")
	user.LastName = r.Form.Get("last_name")
	user.Description = r.Form.Get("description")

	// Append our existing list of users with a new entry
	users = append(users, user)

	//Finally, we redirect the user to the original HTMl page
	// (located at `/assets/`), using the http libraries `Redirect` method
	http.Redirect(w, r, "/home/", http.StatusFound)
}
