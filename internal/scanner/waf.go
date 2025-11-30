```go
package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// DetectWAF checks if a WAF is protecting the target
func DetectWAF(targetURL string) string {
	client := utils.NewHTTPClient(10 * time.Second)
	
	// Payloads that typically trigger WAFs
	testPayloads := []string{
		"../../etc/passwd",
		"<script>alert(1)</script>",
		"' OR 1=1--",
		"SELECT * FROM users",
	}
	
	for _, payload := range testPayloads {
		// Append payload to URL query
		url := targetURL
		if strings.Contains(targetURL, "?") {
			url += "&test=" + payload
		} else {
			url += "?test=" + payload
		}
		
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// 1. Check Headers
		headers := resp.Header
		
		// Cloudflare
		if headers.Get("cf-ray") != "" || headers.Get("__cfduid") != "" || headers.Get("server") == "cloudflare" {
			return "Cloudflare"
		}
		
		// AWS WAF
		if headers.Get("x-amzn-requestid") != "" || headers.Get("x-amz-cf-id") != "" {
			return "AWS WAF"
		}
		
		// Akamai
		if strings.Contains(headers.Get("server"), "AkamaiGHost") {
			return "Akamai"
		}
		
		// Imperva
		if headers.Get("x-iinfo") != "" || strings.Contains(headers.Get("server"), "Imperva") {
			return "Imperva"
		}
		
		// 2. Check Status Codes & Body
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
			// Read a bit of body to check for signatures
			// (Assuming ReadResponseBody is not available or we just read directly)
			// For simplicity, we won't read body here to avoid complexity with closing/reading
			// But usually WAFs return specific pages
			
			// Simple header check for now is safer than reading body if we don't have a helper handy
			// But let's check Server header again
		}
	}
	
	return "None Detected"
}

// AdaptiveEvasion applies evasion techniques when WAF is detected
type EvasionContext struct {
	CaseVariation bool
	URLEncoding   bool
	VerbTampering bool
	SlowDown      bool
	RateLimited   int // Count of 429/403 responses
}

// ApplyEvasion modifies request to evade WAF
func (ec *EvasionContext) ApplyEvasion(req *http.Request, payload string) string {
	if ec.CaseVariation {
		payload = applyCaseVariation(payload)
	}
	
	if ec.URLEncoding {
		payload = applyDoubleEncoding(payload)
	}
	
	if ec.VerbTampering && req.Method == "POST" {
		req.Method = "PUT" // Try alternative verb
	}
	
	return payload
}

// CheckRateLimiting detects if response indicates rate limiting
func (ec *EvasionContext) CheckRateLimiting(statusCode int) bool {
	if statusCode == 429 || statusCode == 403 {
		ec.RateLimited++
		ec.SlowDown = true
		return true
	}
	return false
}

// GetDelay returns adaptive delay based on rate limiting
func (ec *EvasionContext) GetDelay() time.Duration {
	if ec.RateLimited == 0 {
		return 0
	}
	
	// Exponential backoff: 1s, 2s, 4s, 8s (max)
	delay := time.Duration(1<<uint(ec.RateLimited-1)) * time.Second
	if delay > 8*time.Second {
		delay = 8 * time.Second
	}
	return delay
}

func applyCaseVariation(s string) string {
	// PaYmEnT → varies case
	result := ""
	for i, c := range s {
		if i%2 == 0 {
			result += strings.ToUpper(string(c))
		} else {
			result += strings.ToLower(string(c))
		}
	}
	return result
}

func applyDoubleEncoding(s string) string {
	// URL encode twice
	encoded := url.QueryEscape(s)
	return url.QueryEscape(encoded)
}
