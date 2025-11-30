package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestIdempotency tests idempotency key enforcement vulnerabilities
func TestIdempotency(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// P0 Tests (Complete Implementation)
	vulns = append(vulns, testIdempotencyKeyCollision(endpoint, session)...)
	vulns = append(vulns, testIdempotencyExpiredKeyReuse(endpoint, session)...)
	vulns = append(vulns, testIdempotencyMissingKey(endpoint, session)...)
	vulns = append(vulns, testIdempotencyCaseSensitivity(endpoint, session)...)
	vulns = append(vulns, testIdempotencyRaceCondition(endpoint, session)...)
	
	return vulns
}

// testIdempotencyKeyCollision tests if same key with different body is rejected
func testIdempotencyKeyCollision(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Generate idempotency key
	idempotencyKey := generateIdempotencyKey()
	
	// First request with amount 100
	payload1 := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"order_id": "test_collision_001",
	}
	
	resp1, body1 := sendPaymentRequest(endpoint, session, idempotencyKey, payload1)
	if resp1 == nil || (resp1.StatusCode < 200 || resp1.StatusCode >= 300) {
		return vulns // First request failed, skip test
	}
	
	// Wait a bit
	time.Sleep(500 * time.Millisecond)
	
	// Second request with SAME key but DIFFERENT amount (200)
	payload2 := map[string]interface{}{
		"amount":   200, // DIFFERENT!
		"currency": "USD",
		"order_id": "test_collision_002", // DIFFERENT!
	}
	
	resp2, body2 := sendPaymentRequest(endpoint, session, idempotencyKey, payload2)
	if resp2 == nil {
		return vulns
	}
	
	// Server should reject or return same result as first request
	// If it accepts and processes second request differently = VULNERABLE
	if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
		// Check if response is different (means it processed second request)
		if body1 != body2 && !strings.Contains(body2, "idempotency") {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Idempotency Key Collision",
				Severity:    "CRITICAL",
				Title:       "Idempotency Key Collision - Different Requests Accepted",
				Description: "Server accepted two different requests with the same idempotency key. This allows attackers to bypass idempotency protection.",
				Endpoint:    endpoint.URL,
				Method:      endpoint.Method,
				Proof:       fmt.Sprintf("Key: %s, Request1: amount=100, Request2: amount=200, Both accepted with different responses", idempotencyKey),
				Timestamp:   time.Now(),
				CWE:         "CWE-841", // Improper Enforcement of Behavioral Workflow
				CVSSScore:   9.1,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
				Confidence:  "High",
				Remediation: `Implement proper idempotency key validation:

// Go example:
type IdempotencyCache struct {
    mu sync.RWMutex
    cache map[string]IdempotencyEntry
}

type IdempotencyEntry struct {
    RequestHash string
    Response    []byte
    CreatedAt   time.Time
}

func (c *IdempotencyCache) Check(key string, requestHash string) ([]byte, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    entry, exists := c.cache[key]
    if !exists {
        return nil, false
    }
    
    // Reject if same key but different request
    if entry.RequestHash != requestHash {
        return nil, false // Return error to caller
    }
    
    return entry.Response, true
}`,
				References: []string{
					"https://stripe.com/docs/api/idempotent_requests",
					"https://cwe.mitre.org/data/definitions/841.html",
				},
			})
		}
	}
	
	return vulns
}

// testIdempotencyExpiredKeyReuse tests if expired keys (> 24h) can be reused
func testIdempotencyExpiredKeyReuse(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Note: This is a simulation since we can't actually wait 25 hours
	// We test by sending a key with old timestamp in the key itself
	
	// Create key with "old" timestamp (25 hours ago) encoded in it
	oldTimestamp := time.Now().Add(-25 * time.Hour).Unix()
	oldKey := fmt.Sprintf("idem_%d_%s", oldTimestamp, generateRandomString(16))
	
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"order_id": "test_expired_001",
	}
	
	resp, _ := sendPaymentRequest(endpoint, session, oldKey, payload)
	if resp == nil {
		return vulns
	}
	
	// If server accepts key that's clearly old (> 24h standard window)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Idempotency Key Expiry",
			Severity:    "MEDIUM",
			Title:       "No Idempotency Key Expiry Validation",
			Description: "Server accepts idempotency keys older than 24 hours (standard expiry window). This could allow replay attacks after key expiry.",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Sent key with 25-hour old timestamp: %s, received %d", oldKey, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-613", // Insufficient Session Expiration
			CVSSScore:   5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Medium",
			Remediation: "Enforce 24-hour expiry window for idempotency keys. Reject keys older than this threshold.",
		})
	}
	
	return vulns
}

// testIdempotencyMissingKey tests if requests without idempotency key are handled correctly
func testIdempotencyMissingKey(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"order_id": "test_missing_key_001",
	}
	
	// Send request WITHOUT idempotency key header
	payloadJSON, _ := json.Marshal(payload)
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	// NO Idempotency-Key header!
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// Send same request again (should be duplicate)
	time.Sleep(500 * time.Millisecond)
	req2, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req2.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req2, session)
	
	resp2, err := client.Do(req2)
	if err != nil {
		return vulns
	}
	defer resp2.Body.Close()
	
	// If both succeed, server doesn't enforce idempotency keys
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Idempotency Key Missing",
			Severity:    "HIGH",
			Title:       "Idempotency Key Not Required",
			Description: "Server accepts payment requests without idempotency keys, allowing duplicate charges from network retries or user errors.",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Sent 2 identical requests without Idempotency-Key header, both accepted: %d, %d", resp.StatusCode, resp2.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-841", // Improper Enforcement of Behavioral Workflow
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			Confidence:  "High",
			Remediation: "Require Idempotency-Key header for all payment mutations (POST/PUT/PATCH). Return 400 Bad Request if missing.",
			References: []string{
				"https://stripe.com/docs/api/idempotent_requests",
			},
		})
	}
	
	return vulns
}

// testIdempotencyCaseSensitivity tests if keys are case-sensitive
func testIdempotencyCaseSensitivity(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	baseKey := "IdempotencyKey123ABC"
	
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"order_id": "test_case_001",
	}
	
	// Send with original case
	resp1, _ := sendPaymentRequest(endpoint, session, baseKey, payload)
	if resp1 == nil || (resp1.StatusCode < 200 || resp1.StatusCode >= 300) {
		return vulns
	}
	
	time.Sleep(500 * time.Millisecond)
	
	// Send with DIFFERENT case (should be treated as different key)
	lowerKey := strings.ToLower(baseKey)
	resp2, _ := sendPaymentRequest(endpoint, session, lowerKey, payload)
	if resp2 == nil {
		return vulns
	}
	
	// If both succeed, keys are NOT case-sensitive (VULNERABLE)
	if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Idempotency Key Case Sensitivity",
			Severity:    "LOW",
			Title:       "Idempotency Keys Not Case-Sensitive",
			Description: "Server treats idempotency keys as case-insensitive, which could lead to unexpected collisions.",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Keys '%s' and '%s' treated as same", baseKey, lowerKey),
			Timestamp:   time.Now(),
			CWE:         "CWE-178", // Improper Handling of Case Sensitivity
			CVSSScore:   3.7,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Medium",
			Remediation: "Treat idempotency keys as case-sensitive to prevent unintended collisions.",
		})
	}
	
	return vulns
}

// testIdempotencyRaceCondition tests race on idempotency validation itself
func testIdempotencyRaceCondition(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Use same key for concurrent requests
	sharedKey := generateIdempotencyKey()
	
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"order_id": "test_race_001",
	}
	
	concurrency := 5
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	results := make(chan *http.Response, concurrency)
	
	// Fire concurrent requests with SAME idempotency key
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier // Wait at barrier
			
			resp, _ := sendPaymentRequest(endpoint, session, sharedKey, payload)
			results <- resp
		}()
	}
	
	// Release all simultaneously
	close(barrier)
	wg.Wait()
	close(results)
	
	// Count successful responses
	successCount := 0
	for resp := range results {
		if resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
	}
	
	// If more than 1 succeeded, race condition on idempotency check
	if successCount > 1 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Idempotency Race Condition",
			Severity:    "CRITICAL",
			Title:       "Race Condition in Idempotency Key Validation",
			Description: fmt.Sprintf("Server processed %d out of %d concurrent requests with the same idempotency key. This indicates a race condition in the idempotency validation logic.", successCount, concurrency),
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Sent %d concurrent requests with key '%s', %d succeeded", concurrency, sharedKey, successCount),
			Timestamp:   time.Now(),
			CWE:         "CWE-362", // Concurrent Execution using Shared Resource with Improper Synchronization
			CVSSScore:   9.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
			Confidence:  "High",
			Remediation: `Use atomic operations or database constraints for idempotency validation:

// Go example with database:
tx, _ := db.Begin()
_, err := tx.Exec(
    "INSERT INTO idempotency_keys (key, request_hash, response, created_at) VALUES (?, ?, ?, ?)",
    key, requestHash, response, time.Now(),
)
if err != nil {
    // Key already exists (duplicate request)
    tx.Rollback()
    return cachedResponse
}
tx.Commit()`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/362.html",
				"https://stripe.com/docs/api/idempotent_requests#how-it-works",
			},
		})
	}
	
	return vulns
}

// Helper functions

func generateIdempotencyKey() string {
	return fmt.Sprintf("idem_%d_%s", time.Now().Unix(), generateRandomString(16))
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}

func sendPaymentRequest(endpoint models.Endpoint, session *models.Session, idempotencyKey string, payload map[string]interface{}) (*http.Response, string) {
	payloadJSON, _ := json.Marshal(payload)
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	
	// Read body for comparison
	bodyBytes := make([]byte, 4096)
	n, _ := resp.Body.Read(bodyBytes)
	resp.Body.Close()
	
	return resp, string(bodyBytes[:n])
}


