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

// TestAmountValidation tests for amount validation vulnerabilities
func TestAmountValidation(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	if endpoint.Method != "POST" && endpoint.Method != "PUT" {
		return vulns
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	// Test cases for precision attacks
	testCases := []struct {
		name   string
		amount interface{}
	}{
		{"High Precision", 10.123456789}, // Rounding exploit?
		{"Overflow", 99999999999999999999.99},
		{"String Number", "100"},
	}
	
	for _, tc := range testCases {
		payload := map[string]interface{}{
			"amount": tc.amount,
			"currency": "USD",
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
		
		// If 500 error, might be unhandled exception (DoS risk or logic error)
		if resp.StatusCode == 500 {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Amount Validation",
				Severity:    "LOW",
				Title:       fmt.Sprintf("Unhandled Amount Format (%s)", tc.name),
				Description: "Endpoint returned 500 Internal Server Error for unusual amount format.",
				Endpoint:    endpoint.URL,
				Method:      endpoint.Method,
				Timestamp:   time.Now(),
			})
		}
	}
	
	return vulns
}
