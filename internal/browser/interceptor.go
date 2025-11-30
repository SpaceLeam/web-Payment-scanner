package browser

import (
	"fmt"
	"sync"
	
	"github.com/playwright-community/playwright-go"
)

// NetworkRequest represents an intercepted network request
type NetworkRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
}

// NetworkResponse represents an intercepted network response
type NetworkResponse struct {
	URL        string
	Status     int
	Headers    map[string]string
	Body       string
}

// RequestInterceptor handles network request interception
type RequestInterceptor struct {
	requests  []NetworkRequest
	responses []NetworkResponse
	mu        sync.Mutex
}

// NewInterceptor creates a new request interceptor
func NewInterceptor() *RequestInterceptor {
	return &RequestInterceptor{
		requests:  make([]NetworkRequest, 0),
		responses: make([]NetworkResponse, 0),
	}
}

// EnableInterception enables network request/response interception
func (ri *RequestInterceptor) EnableInterception(page playwright.Page) error {
	// Listen for requests
	page.On("request", func(request playwright.Request) {
		ri.mu.Lock()
		defer ri.mu.Unlock()
		
		headers := make(map[string]string)
		for k, v := range request.Headers() {
			headers[k] = v
		}
		
		ri.requests = append(ri.requests, NetworkRequest{
			URL:     request.URL(),
			Method:  request.Method(),
			Headers: headers,
			Body:    request.PostData(),
		})
	})
	
	// Listen for responses
	page.On("response", func(response playwright.Response) {
		ri.mu.Lock()
		defer ri.mu.Unlock()
		
		headers := make(map[string]string)
		for k, v := range response.Headers() {
			headers[k] = v
		}
		
		// Try to get response body (may fail for some responses)
		body, _ := response.Text()
		
		ri.responses = append(ri.responses, NetworkResponse{
			URL:     response.URL(),
			Status:  response.Status(),
			Headers: headers,
			Body:    body,
		})
	})
	
	return nil
}

// GetRequests returns all intercepted requests
func (ri *RequestInterceptor) GetRequests() []NetworkRequest {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	
	// Return a copy to avoid race conditions
	requests := make([]NetworkRequest, len(ri.requests))
	copy(requests, ri.requests)
	return requests
}

// GetResponses returns all intercepted responses
func (ri *RequestInterceptor) GetResponses() []NetworkResponse {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	
	// Return a copy
	responses := make([]NetworkResponse, len(ri.responses))
	copy(responses, ri.responses)
	return responses
}

// GetRequestsByURL returns requests matching a URL pattern
func (ri *RequestInterceptor) GetRequestsByURL(urlPattern string) []NetworkRequest {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	
	matches := make([]NetworkRequest, 0)
	for _, req := range ri.requests {
		// Simple contains check (can be improved with regex)
		if contains(req.URL, urlPattern) {
			matches = append(matches, req)
		}
	}
	
	return matches
}

// Clear clears all intercepted data
func (ri *RequestInterceptor) Clear() {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	
	ri.requests = make([]NetworkRequest, 0)
	ri.responses = make([]NetworkResponse, 0)
}

// PrintSummary prints a summary of intercepted traffic
func (ri *RequestInterceptor) PrintSummary() {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	
	fmt.Printf("Intercepted Requests: %d\n", len(ri.requests))
	fmt.Printf("Intercepted Responses: %d\n", len(ri.responses))
	
	// Show payment-related requests
	paymentReqs := 0
	for _, req := range ri.requests {
		if isPaymentRelated(req.URL) {
			paymentReqs++
		}
	}
	fmt.Printf("Payment-related requests: %d\n", paymentReqs)
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func isPaymentRelated(url string) bool {
	keywords := []string{"payment", "checkout", "order", "cart", "transaction", "pay"}
	lowerURL := url
	
	for _, keyword := range keywords {
		if contains(lowerURL, keyword) {
			return true
		}
	}
	return false
}
