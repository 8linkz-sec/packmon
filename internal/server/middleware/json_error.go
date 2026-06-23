package middleware

import (
	"encoding/json"
	"net/http"
)

type jsonErrorResponse struct {
	Error string `json:"error"`
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonErrorResponse{Error: message})
}
