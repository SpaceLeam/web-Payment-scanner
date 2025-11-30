package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestPriceManipulation tests for price tampering vulnerabilities
func TestPriceManipulation(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Only relevant for requests with body (POST/PUT)
	if endpoint.Method != "POST" && endpoint.Method != "PUT" {
		return vulns
	}
	
	// Test cases
	testCases := []struct {
		name  string
		value interface{} // float64 or string
	}{
		{"Negative Price", -100.00},
		{"Zero Price", 0.00},
		{"Tiny Price", 0.01},
		{"String Price", "0.00"},
		{"Negative String", "-100"},
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	for _, tc := range testCases {
		// Construct payload (simplified)
		// In reality, we need to parse the original body and replace the price field
		// This requires knowing the schema or heuristic field replacement
		payload := map[string]interface{}{
			"amount": tc.value,
			"price":  tc.value,
			"cost":   tc.value,
		}
		
		jsonBody, _ := json.Marshal(payload)
		
		req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		// Add auth
		for k, v := range session.Cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// Analysis
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// If server accepted negative/zero price
			vulns = append(vulns, models.Vulnerability{
				Type:        "Price Manipulation",
				Severity:    "CRITICAL",
				Title:       fmt.Sprintf("Price Manipulation (%s)", tc.name),
				Description: fmt.Sprintf("Endpoint accepted %s value.", tc.name),
				Endpoint:    endpoint.URL,
				Method:      endpoint.Method,
				Payload:     string(jsonBody),
				Timestamp:   time.Now(),
			})
		}
	}
	
	return vulns
}
