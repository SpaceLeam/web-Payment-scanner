package utils

import (
	"io"
	"net/http"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
)

// MakeWSAwareRequest creates an HTTP request with WebSocket session tokens
func MakeWSAwareRequest(client *http.Client, method, url string, session *models.Session, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	
	// Add cookies
	for k, v := range session.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	
	// Add session token from WebSocket
	if session.SessionToken != "" {
		req.Header.Set("X-Session-Token", session.SessionToken)
		req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	}
	
	// Add URL token to query/header
	if session.URLToken != "" {
		req.Header.Set("X-URL-Token", session.URLToken)
	}
	
	return client.Do(req)
}
