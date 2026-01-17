package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type req struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type resp struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var q req
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Username == "" || q.Password == "" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		out := resp{
			UserID: "user-" + q.Username, // demo stable id
			Name:   "Demo " + q.Username,
			Email:  q.Username + "@demo.local",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	log.Println("LoginAPI listening on :8090")
	log.Fatal(http.ListenAndServe(":8090", nil))
}
