package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
)

// TestRaceCondition tests for race condition vulnerabilities
// P0 ENHANCED: HTTP/2 pooling, connection warming, sync barrier
func TestRaceCondition(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Enhanced race condition test with connection pooling
	vulns = append(vulns, testRaceConditionEnhanced(endpoint, session, 10)...)
	
	// Multi-endpoint race condition test
	vulns = append(vulns, testMultiEndpointRace(endpoint, session)...)
	
	return vulns
}

// testRaceConditionEnhanced uses HTTP/2 pooling and connection warming
func testRaceConditionEnhanced(endpoint models.Endpoint, session *models.Session, concurrency int) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// 1. Create HTTP/2 client with connection pooling
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     90 * time.Second,
			// Force HTTP/2 if available
			ForceAttemptHTTP2: true,
		},
	}
	
	// 2. Pre-warm connections (send dummy requests)
	// utils.Logger.Info("Warming up connections...")
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", endpoint.URL, nil)
		if err != nil {
			continue
		}
		addAuthHeaders(req, session)
		client.Do(req) // Ignore response, just warming connection
	}
	time.Sleep(100 * time.Millisecond) // Let connections stabilize
	
	// 3. Prepare payload
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD",
		"action":   "debit",
	}
	payloadJSON, _ := json.Marshal(payload)
	
	// 4. Synchronization barrier for near-simultaneous release
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	results := make(chan *RaceResult, concurrency)
	
	// 5. Launch concurrent requests
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Prepare request
			req, err := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			addAuthHeaders(req, session)
			
			// Wait at barrier
			<-barrier
			
			// Record start time with nanosecond precision
			startTime := time.Now()
			
			// Fire!
			resp, err := client.Do(req)
			
			// Record end time
			endTime := time.Now()
			
			if err != nil {
				return
			}
			defer resp.Body.Close()
			
			// Read response body
			bodyBytes := make([]byte, 4096)
			n, _ := resp.Body.Read(bodyBytes)
			
			results <- &RaceResult{
				ID:         id,
				StatusCode: resp.StatusCode,
				Body:       string(bodyBytes[:n]),
				StartTime:  startTime,
				EndTime:    endTime,
				Duration:   endTime.Sub(startTime),
			}
		}(i)
	}
	
	// 6. Release all goroutines simultaneously
	close(barrier)
	wg.Wait()
	close(results)
	
	// 7. Analyze results for race condition indicators
	var raceResults []*RaceResult
	for result := range results {
		raceResults = append(raceResults, result)
	}
	
	vulns = append(vulns, analyzeRaceResults(endpoint, raceResults)...)
	
	return vulns
}

// testMultiEndpointRace tests race between validation and confirmation endpoints
func testMultiEndpointRace(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Common patterns for multi-endpoint races:
	// - /validate + /confirm
	// - /reserve + /commit
	// - /check + /execute
	
	// Try to infer confirmation endpoint
	confirmEndpoints := inferConfirmationEndpoints(endpoint.URL)
	
	for _, confirmURL := range confirmEndpoints {
		// Test if racing validation with confirmation causes issues
		vuln := testValidateConfirmRace(endpoint.URL, confirmURL, session)
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}
	
	return vulns
}

type RaceResult struct {
	ID         int
	StatusCode int
	Body       string
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
}

func analyzeRaceResults(endpoint models.Endpoint, results []*RaceResult) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	if len(results) == 0 {
		return vulns
	}
	
	// Count successful responses
	successCount := 0
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			successCount++
		}
	}
	
	// If more than 1 succeeded, potential race condition
	if successCount > 1 {
		// Check for timing anomalies (negative timestamps)
		hasNegativeTime := false
		minDuration := results[0].Duration
		maxDuration := results[0].Duration
		
		for _, r := range results {
			if r.Duration < minDuration {
				minDuration = r.Duration
			}
			if r.Duration > maxDuration {
				maxDuration = r.Duration
			}
			
			// Check if response came before request (timing attack indicator)
			if r.Duration < 0 {
				hasNegativeTime = true
			}
		}
		
		timingSpread := maxDuration - minDuration
		
		vulns = append(vulns, models.Vulnerability{
			Type:        "Race Condition",
			Severity:    "CRITICAL",
			Title:       "Concurrent Request Race Condition Detected",
			Description: fmt.Sprintf("Server processed %d out of %d concurrent identical requests successfully. This indicates lack of proper concurrency control.", successCount, len(results)),
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("%d concurrent requests sent, %d succeeded. Timing spread: %v. Negative time: %v", len(results), successCount, timingSpread, hasNegativeTime),
			Timestamp:   time.Now(),
			CWE:         "CWE-362", // Concurrent Execution using Shared Resource
			CVSSScore:   9.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
			Confidence:  "High",
			Remediation: `Implement proper concurrency control:

// Go example with database transaction:
tx, _ := db.Begin()
tx.Exec("SELECT balance FROM accounts WHERE id = ? FOR UPDATE", accountID)
// Process debit
tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, accountID)
tx.Commit()

// Or use distributed lock:
lock := redisClient.SetNX(ctx, lockKey, "1", 5*time.Second)
if !lock {
    return errors.New("operation already in progress")
}
defer redisClient.Del(ctx, lockKey)`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/362.html",
				"https://owasp.org/www-community/vulnerabilities/Race_Conditions",
			},
		})
	}
	
	return vulns
}

func inferConfirmationEndpoints(validateURL string) []string {
	// Try common patterns
	endpoints := []string{}
	
	patterns := map[string]string{
		"/validate": "/confirm",
		"/check":    "/execute",
		"/reserve":  "/commit",
		"/prepare":  "/complete",
		"/verify":   "/process",
	}
	
	for from, to := range patterns {
		if contains(validateURL, from) {
			confirmURL := replace(validateURL, from, to)
			endpoints = append(endpoints, confirmURL)
		}
	}
	
	return endpoints
}

func testValidateConfirmRace(validateURL, confirmURL string, session *models.Session) *models.Vulnerability {
	// This would require actual implementation of racing two different endpoints
	// Simplified for now - return nil (no vulnerability found)
	// Full implementation would:
	// 1. Send request to /validate
	// 2. Immediately (concurrently) send request to /confirm
	// 3. Check if /confirm succeeds before /validate completes
	
	return nil // TODO: Full multi-endpoint race implementation
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func replace(s, old, new string) string {
	// Simple replace implementation
	result := ""
	i := 0
	for i < len(s) {
		if i <= len(s)-len(old) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}
