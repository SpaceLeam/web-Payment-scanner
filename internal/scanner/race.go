package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestRaceCondition tests for race conditions on an endpoint
func TestRaceCondition(endpoint models.Endpoint, session *models.Session, concurrency int) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Only test POST/PUT requests usually
	if endpoint.Method != "POST" && endpoint.Method != "PUT" {
		return vulns
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	// Prepare synchronization
	var wg sync.WaitGroup
	startSignal := make(chan struct{})
	results := make(chan int, concurrency)
	
	// Launch workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Wait for signal
			<-startSignal
			
			// Send request
			// Note: In real impl, we need the actual payload/body
			// For now, we assume a replay of a captured request or generic payload
			req, _ := http.NewRequest(endpoint.Method, endpoint.URL, nil)
			
			// Add headers/cookies
			for k, v := range session.Headers {
				req.Header.Set(k, v)
			}
			for k, v := range session.Cookies {
				req.AddCookie(&http.Cookie{Name: k, Value: v})
			}
			
			resp, err := client.Do(req)
			if err == nil {
				results <- resp.StatusCode
				resp.Body.Close()
			} else {
				results <- 0
			}
		}()
	}
	
	// Release all workers at once
	close(startSignal)
	wg.Wait()
	close(results)
	
	// Analyze results
	successCount := 0
	statusCodes := make(map[int]int)
	
	for code := range results {
		if code >= 200 && code < 300 {
			successCount++
		}
		statusCodes[code]++
	}
	
	// Heuristic: If multiple requests succeeded where only 1 should (e.g. coupon claim), it's a race
	// This logic needs refinement based on endpoint type (e.g. "claim", "transfer", "pay")
	if successCount > 1 && isSingleUseEndpoint(endpoint.URL) {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Race Condition",
			Severity:    "HIGH",
			Title:       "Potential Race Condition Detected",
			Description: fmt.Sprintf("Endpoint accepted %d concurrent requests successfully.", successCount),
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Timestamp:   time.Now(),
		})
	}
	
	return vulns
}

func isSingleUseEndpoint(url string) bool {
	keywords := []string{"claim", "redeem", "transfer", "pay", "checkout", "apply"}
	lower := strings.ToLower(url)
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}
