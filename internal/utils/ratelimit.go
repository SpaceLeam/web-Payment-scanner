package utils

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	requests chan struct{}
	interval time.Duration
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter with specified requests per second
func NewRateLimiter(reqPerSecond int) *RateLimiter {
	if reqPerSecond <= 0 {
		reqPerSecond = 1 // Minimum 1
	}
	
	rl := &RateLimiter{
		requests: make(chan struct{}, reqPerSecond),
		interval: time.Second / time.Duration(reqPerSecond),
	}
	
	// Fill bucket initially
	for i := 0; i < reqPerSecond; i++ {
		rl.requests <- struct{}{}
	}
	
	// Refill routine
	go func() {
		ticker := time.NewTicker(rl.interval)
		defer ticker.Stop()
		for range ticker.C {
			select {
			case rl.requests <- struct{}{}:
			default:
				// Bucket full, skip
			}
		}
	}()
	
	return rl
}

// Wait blocks until a token is available
func (rl *RateLimiter) Wait() {
	<-rl.requests
}
