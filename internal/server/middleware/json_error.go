package middleware

import (
	"encoding/json"
	"net/http"
)

type jsonErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonErrorResponse{Error: message, Code: jsonErrorCodeForStatus(status)})
}

func jsonErrorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "auth_failed"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return "unsupported"
	default:
		return "internal_error"
	}
}
