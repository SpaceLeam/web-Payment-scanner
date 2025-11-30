package utils

import (
	"sync"
	"time"
)

// RateLimiter handles request rate limiting
type RateLimiter struct {
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
