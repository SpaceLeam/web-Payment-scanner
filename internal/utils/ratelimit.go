package utils

import (
	"sync"
	"time"
)

// RateLimiter handles request rate limiting
type RateLimiter struct {
	rps       int
	limiter   *time.Ticker
	mu        sync.Mutex
	endpoints map[string]*EndpointState // Per-endpoint tracking
}

// EndpointState tracks rate limiting per endpoint
type EndpointState struct {
	RateLimited   int           // Consecutive 429/403 count
	LastBackoff   time.Duration // Last backoff duration
	LastRequest   time.Time
	ShouldPause   bool          // Auto-pause on sustained rate limiting
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		rps = 10 // Default: 10 req/sec
	}
	
	return &RateLimiter{
		rps:       rps,
		limiter:   time.NewTicker(time.Second / time.Duration(rps)),
		endpoints: make(map[string]*EndpointState),
	}
}

// Wait pauses until the next request can be sent
func (rl *RateLimiter) Wait(endpoint string) {
	rl.mu.Lock()
	state, exists := rl.endpoints[endpoint]
	if !exists {
		state = &EndpointState{}
		rl.endpoints[endpoint] = state
	}
	rl.mu.Unlock()
	
	// Check if paused due to sustained rate limiting
	if state.ShouldPause {
		time.Sleep(10 * time.Second) // Long pause
		state.ShouldPause = false
	}
	
	// Apply adaptive backoff if rate limited
	if state.RateLimited > 0 {
		backoff := state.LastBackoff
		if backoff == 0 {
			backoff = 1 * time.Second
		}
		time.Sleep(backoff)
	}
	
	<-rl.limiter.C
	state.LastRequest = time.Now()
}

// RecordResponse records endpoint response for rate limit detection
func (rl *RateLimiter) RecordResponse(endpoint string, statusCode int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	state, exists := rl.endpoints[endpoint]
	if !exists {
		state = &EndpointState{}
		rl.endpoints[endpoint] = state
	}
	
	// Detect rate limiting
	if statusCode == 429 || statusCode == 403 {
		state.RateLimited++
		
		// Exponential backoff: 1s → 2s → 4s → 8s (max)
		state.LastBackoff = time.Duration(1<<uint(state.RateLimited-1)) * time.Second
		if state.LastBackoff > 8*time.Second {
			state.LastBackoff = 8 * time.Second
		}
		
		// Auto-pause on 3 consecutive rate limits
		if state.RateLimited >= 3 {
			state.ShouldPause = true
		}
	} else {
		// Reset on success
		state.RateLimited = 0
		state.LastBackoff = 0
	}
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
	rl.limiter.Stop()
}
