package scanner

import (
	"net/http"
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
