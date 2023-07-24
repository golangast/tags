package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("Hello World")

	u := User{

		Email: "john@example.com",
		Pkey:  "3243432432",
		Prkey: "dfsfdsfds",
	}
	byteInfo, err := json.Marshal(u) // has two values returned
	// check if there was an error returned first
	if err != nil {
		fmt.Println(err)
		// handle your error here
	}

	w.Header().Set("Content-Type", "application/json")
	// error here
	req, err := http.NewRequest("POST", "https://fc1f-2601-244-5680-115b-81c0-8ad-cfe0-4840.ngrok.io/health", bytes.NewBuffer(byteInfo))

	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println(req)
	// fmt.Println(req.Body)
	// fmt.Println(req.Header)
	defer req.Body.Close()
}

type User struct {
	Email string `json:"email" validate:"required,email"`
	Pkey  string `json:"pkey" validate:"required"`
	Prkey string `json:"prkey" validate:"required"`
}
