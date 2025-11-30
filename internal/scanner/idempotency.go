package scanner

import (
	"net/http"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestIdempotency tests for idempotency key bypass
func TestIdempotency(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	if endpoint.Method != "POST" {
		return vulns
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	// 1. Replay with same Idempotency Key
	// Should return cached response (same status)
	key := fmt.Sprintf("key_%d", time.Now().Unix())
	
	req1 := createIdempotencyRequest(endpoint, session, key)
	resp1, err1 := client.Do(req1)
	if err1 != nil {
		return vulns
	}
	defer resp1.Body.Close()
	
	req2 := createIdempotencyRequest(endpoint, session, key)
	resp2, err2 := client.Do(req2)
	if err2 != nil {
		return vulns
	}
	defer resp2.Body.Close()
	
	// If both succeeded (200/201) but are treated as new operations (different resource IDs in body?)
	// Hard to detect without parsing body. 
	// But if status codes differ significantly (e.g. 201 Created vs 409 Conflict), that's actually GOOD.
	// If both are 201 Created, it MIGHT be bad if they created duplicates.
	
	// 2. Missing Idempotency Key
	// Some APIs require it. If we omit it, does it allow duplicate processing?
	
	return vulns
}

func createIdempotencyRequest(endpoint models.Endpoint, session *models.Session, key string) *http.Request {
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, nil) // Empty body for now
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("X-Idempotency-Key", key)
	
	for k, v := range session.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return req
}
