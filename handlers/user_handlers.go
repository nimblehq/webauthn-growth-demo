package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	Species     string `json:"species"`
	Description string `json:"description"`
}

var birds []User

func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	//Convert the "birds" variable to json
	birdListBytes, err := json.Marshal(birds)

	// If there is an error, print it to the console, and return a server
	// error response to the user
	if err != nil {
		fmt.Println(fmt.Errorf("Error: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// If all goes well, write the JSON list of birds to the response
	w.Write(birdListBytes)
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
	user.Species = r.Form.Get("species")
	user.Description = r.Form.Get("description")

	// Append our existing list of birds with a new entry
	birds = append(birds, user)

	//Finally, we redirect the user to the original HTMl page
	// (located at `/assets/`), using the http libraries `Redirect` method
	http.Redirect(w, r, "/home/", http.StatusFound)
}
