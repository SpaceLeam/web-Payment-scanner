package scanner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestCallbackAuth tests for webhook/callback authentication vulnerabilities
func TestCallbackAuth(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Only relevant for callback endpoints
	if !isCallbackEndpoint(endpoint.URL) {
		return vulns
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	// Payload simulating a payment success
	payload := map[string]interface{}{
		"event":  "payment.success",
		"amount": 1000,
		"status": "paid",
		"id":     "evt_test123",
	}
	jsonBody, _ := json.Marshal(payload)
	
	// 1. Test Missing Signature
	// Send request without any signature header
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		// If accepted (2xx), it's vulnerable
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Callback Security",
				Severity:    "HIGH",
				Title:       "Missing Signature Validation",
				Description: "Endpoint accepted webhook without signature header.",
				Endpoint:    endpoint.URL,
				Method:      "POST",
				Timestamp:   time.Now(),
			})
		}
	}
	
	// 2. Test Invalid Signature
	// Send request with invalid signature
	req2, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Signature", "invalid_signature_hex")
	req2.Header.Set("Stripe-Signature", "t=123,v1=invalid")
	
	resp2, err := client.Do(req2)
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Callback Security",
				Severity:    "HIGH",
				Title:       "Weak Signature Validation",
				Description: "Endpoint accepted webhook with invalid signature.",
				Endpoint:    endpoint.URL,
				Method:      "POST",
				Timestamp:   time.Now(),
			})
		}
	}
	
	return vulns
}

func isCallbackEndpoint(url string) bool {
	keywords := []string{"callback", "webhook", "ipn", "notify", "notification"}
	lower := strings.ToLower(url)
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}
