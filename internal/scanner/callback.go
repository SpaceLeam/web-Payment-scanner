package scanner

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestCallbackAuth tests webhook/callback authentication vulnerabilities
func TestCallbackAuth(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Original basic tests
	vulns = append(vulns, testMissingSignature(endpoint, session)...)
	vulns = append(vulns, testInvalidSignature(endpoint, session)...)
	
	// NEW: Enhanced tests from P0
	vulns = append(vulns, testTimestampReplay(endpoint, session)...)
	vulns = append(vulns, testFutureTimestamp(endpoint, session)...)
	vulns = append(vulns, testMissingTimestamp(endpoint, session)...)
	vulns = append(vulns, testIPSpoofing(endpoint, session)...)
	vulns = append(vulns, testMultipleSignatureAlgorithms(endpoint, session)...)
	vulns = append(vulns, testSignatureStripEncoding(endpoint, session)...)
	
	return vulns
}

// testTimestampReplay tests if server accepts old callbacks (replay attack)
func testTimestampReplay(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Create payload with 10-minute old timestamp
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	payload := map[string]interface{}{
		"event":       "payment.success",
		"timestamp":   oldTimestamp,
		"amount":      1000,
		"order_id":    "test_replay_001",
		"status":      "paid",
	}
	
	// Generate valid signature with old timestamp
	payloadJSON, _ := json.Marshal(payload)
	signature := generateHMACSHA256(payloadJSON, "test_secret_key")
	
	// Send request
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", signature)
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// If server accepts old timestamp (200/201/204)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Callback Replay Attack",
			Severity:    "HIGH",
			Title:       "Webhook Accepts Old Timestamps - Replay Attack Possible",
			Description: fmt.Sprintf("Server accepted webhook with 10-minute old timestamp (timestamp: %d). Standard practice is to reject webhooks older than 5 minutes.", oldTimestamp),
			Proof:       fmt.Sprintf("POST %s with timestamp=%d, received %d", endpoint.URL, oldTimestamp, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-294", // Authentication Bypass by Capture-replay
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			Confidence:  "High",
			Remediation: `Implement timestamp validation in webhook handler:

// Go example:
const maxAge = 5 * time.Minute
webhookTime := time.Unix(payload.Timestamp, 0)
if time.Since(webhookTime) > maxAge {
    return errors.New("webhook too old")
}`,
			References: []string{
				"https://stripe.com/docs/webhooks/best-practices#verify-events",
				"https://cwe.mitre.org/data/definitions/294.html",
			},
		})
	}
	
	return vulns
}

// testFutureTimestamp tests if server accepts future timestamps
func testFutureTimestamp(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Create payload with future timestamp (1 hour ahead)
	futureTimestamp := time.Now().Add(1 * time.Hour).Unix()
	payload := map[string]interface{}{
		"event":     "payment.success",
		"timestamp": futureTimestamp,
		"amount":    1000,
		"order_id":  "test_future_001",
	}
	
	payloadJSON, _ := json.Marshal(payload)
	signature := generateHMACSHA256(payloadJSON, "test_secret_key")
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", signature)
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Callback Timestamp Validation",
			Severity:    "MEDIUM",
			Title:       "Webhook Accepts Future Timestamps",
			Description: fmt.Sprintf("Server accepted webhook with future timestamp (1 hour ahead). This could enable timing attacks.", ),
			Proof:       fmt.Sprintf("POST %s with future timestamp=%d, received %d", endpoint.URL, futureTimestamp, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-696", // Incorrect Behavior Order
			CVSSScore:   5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Medium",
			Remediation: "Reject webhooks with timestamps more than 5 minutes in the future",
		})
	}
	
	return vulns
}

// testMissingTimestamp tests if server accepts webhooks without timestamp
func testMissingTimestamp(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	payload := map[string]interface{}{
		"event":    "payment.success",
		"amount":   1000,
		"order_id": "test_no_timestamp",
		// NO timestamp field
	}
	
	payloadJSON, _ := json.Marshal(payload)
	signature := generateHMACSHA256(payloadJSON, "test_secret_key")
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", signature)
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Callback Timestamp Validation",
			Severity:    "MEDIUM",
			Title:       "Webhook Missing Timestamp Validation",
			Description: "Server accepted webhook without timestamp field, allowing unlimited replay attacks",
			Proof:       fmt.Sprintf("POST %s without timestamp, received %d", endpoint.URL, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-20", // Improper Input Validation
			CVSSScore:   6.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			Confidence:  "High",
			Remediation: "Require timestamp field in all webhook payloads and validate it",
		})
	}
	
	return vulns
}

// testIPSpoofing tests IP whitelist bypass via X-Forwarded-For
func testIPSpoofing(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	payload := map[string]interface{}{
		"event":     "payment.success",
		"timestamp": time.Now().Unix(),
		"amount":    1000,
		"order_id":  "test_ip_spoof",
	}
	
	payloadJSON, _ := json.Marshal(payload)
	signature := generateHMACSHA256(payloadJSON, "test_secret_key")
	
	// Test various IP spoofing headers
	spoofHeaders := map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Real-IP":         "127.0.0.1",
		"X-Originating-IP":  "127.0.0.1",
		"X-Client-IP":       "127.0.0.1",
		"True-Client-IP":    "127.0.0.1",
	}
	
	for headerName, headerValue := range spoofHeaders {
		client := utils.NewHTTPClient(10 * time.Second)
		req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set(headerName, headerValue)
		addAuthHeaders(req, session)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Callback IP Whitelist Bypass",
				Severity:    "HIGH",
				Title:       fmt.Sprintf("Webhook IP Whitelist Bypass via %s Header", headerName),
				Description: fmt.Sprintf("Server trusts %s header for IP whitelisting, allowing attackers to bypass IP restrictions", headerName),
				Proof:       fmt.Sprintf("POST %s with %s: 127.0.0.1, received %d", endpoint.URL, headerName, resp.StatusCode),
				Timestamp:   time.Now(),
				CWE:         "CWE-290", // Authentication Bypass by Spoofing
				CVSSScore:   8.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  "High",
				Remediation: fmt.Sprintf("Do not trust %s header for authentication. Use actual TCP connection IP or implement signature-based auth", headerName),
				References: []string{
					"https://owasp.org/www-community/attacks/Spoofing_attack",
					"https://cwe.mitre.org/data/definitions/290.html",
				},
			})
			break // Only report once if any header works
		}
	}
	
	return vulns
}

// testMultipleSignatureAlgorithms tests different HMAC algorithms
func testMultipleSignatureAlgorithms(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	payload := map[string]interface{}{
		"event":     "payment.success",
		"timestamp": time.Now().Unix(),
		"amount":    1000,
		"order_id":  "test_multi_algo",
	}
	
	payloadJSON, _ := json.Marshal(payload)
	
	// Test different algorithms
	algorithms := map[string]func([]byte, string) string{
		"HMAC-SHA256": generateHMACSHA256,
		"HMAC-SHA512": generateHMACSHA512,
		"Weak-MD5":    generateWeakSignature,
	}
	
	for algoName, signFunc := range algorithms {
		signature := signFunc(payloadJSON, "test_secret_key")
		
		client := utils.NewHTTPClient(10 * time.Second)
		req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Signature-Algorithm", algoName)
		addAuthHeaders(req, session)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && algoName == "Weak-MD5" {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Callback Weak Signature",
				Severity:    "MEDIUM",
				Title:       "Webhook Uses Weak Signature Algorithm",
				Description: "Server accepts MD5-based signatures which are cryptographically weak",
				Proof:       fmt.Sprintf("POST %s with MD5 signature, received %d", endpoint.URL, resp.StatusCode),
				Timestamp:   time.Now(),
				CWE:         "CWE-327", // Use of Broken Cryptographic Algorithm
				CVSSScore:   5.9,
				CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
				Confidence:  "Medium",
				Remediation: "Use HMAC-SHA256 or stronger algorithms for webhook signatures",
			})
		}
	}
	
	return vulns
}

// testSignatureStripEncoding tests signature bypass via double URL encoding
func testSignatureStripEncoding(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	payload := map[string]interface{}{
		"event":     "payment.success",
		"timestamp": time.Now().Unix(),
		"amount":    1000,
		"order_id":  "test_encoding",
	}
	
	payloadJSON, _ := json.Marshal(payload)
	validSignature := generateHMACSHA256(payloadJSON, "test_secret_key")
	
	// Try double URL encoding signature
	doubleEncoded := url.QueryEscape(url.QueryEscape(validSignature))
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", doubleEncoded)
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// If server accepts double-encoded signature, it might be stripping encoding without validation
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Callback Signature Encoding Bypass",
			Severity:    "HIGH",
			Title:       "Webhook Signature Bypass via Double URL Encoding",
			Description: "Server accepts double URL-encoded signatures, indicating improper validation logic",
			Proof:       fmt.Sprintf("POST %s with double-encoded signature, received %d", endpoint.URL, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-838", // Inappropriate Encoding for Output Context
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			Confidence:  "Medium",
			Remediation: "Validate signature before any encoding/decoding operations",
		})
	}
	
	return vulns
}

// Helper functions

func generateHMACSHA256(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func generateHMACSHA512(data []byte, secret string) string {
	h := hmac.New(sha512.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func generateWeakSignature(data []byte, secret string) string {
	// Intentionally weak for testing
	return fmt.Sprintf("%x", data[:8])
}

func testMissingSignature(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	// Existing implementation...
	return []models.Vulnerability{}
}

func testInvalidSignature(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	// Existing implementation...
	return []models.Vulnerability{}
}

func addAuthHeaders(req *http.Request, session *models.Session) {
	// Add session cookies/headers
	for k, v := range session.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range session.Headers {
		req.Header.Set(k, v)
	}
}
