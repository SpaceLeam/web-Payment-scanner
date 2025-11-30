package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestOTPSecurity tests for OTP/2FA vulnerabilities
func TestOTPSecurity(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Only relevant for OTP endpoints
	if !isOTPEndpoint(endpoint.URL) {
		return vulns
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	// 1. Test Rate Limiting
	// Send 20 requests rapidly with wrong OTPs
	rateLimitVuln := testRateLimit(client, endpoint, session)
	if rateLimitVuln != nil {
		vulns = append(vulns, *rateLimitVuln)
	}
	
	// 2. Test OTP Brute Force (small range)
	// In a real test we might try 0000-9999 but that takes time
	// Here we just check if we get different responses for different inputs
	// or if we can bypass it
	
	return vulns
}

func testRateLimit(client *http.Client, endpoint models.Endpoint, session *models.Session) *models.Vulnerability {
	requestCount := 20
	allowedCount := 0
	
	for i := 0; i < requestCount; i++ {
		// Construct payload with wrong OTP
		payload := fmt.Sprintf(`{"otp": "%06d"}`, i)
		req, _ := http.NewRequest(endpoint.Method, endpoint.URL, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		
		// Add auth
		for k, v := range session.Cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		// If we don't get 429 Too Many Requests, count as allowed
		if resp.StatusCode != 429 {
			allowedCount++
		}
	}
	
	// If all requests were allowed, potential rate limit issue
	if allowedCount == requestCount {
		return &models.Vulnerability{
			Type:        "OTP Security",
			Severity:    "MEDIUM",
			Title:       "Missing Rate Limiting on OTP",
			Description: fmt.Sprintf("Endpoint allowed %d requests without rate limiting (429).", requestCount),
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Timestamp:   time.Now(),
		}
	}
	
	return nil
}

func isOTPEndpoint(url string) bool {
	keywords := []string{"otp", "2fa", "mfa", "verify", "code"}
	lower := strings.ToLower(url)
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}
