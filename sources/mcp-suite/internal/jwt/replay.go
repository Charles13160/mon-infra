package jwt

import (
	"sync"
	"time"
)

type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

func NewReplayCache() *ReplayCache {
	rc := &ReplayCache{
		entries: make(map[string]time.Time),
		ttl:     10 * time.Minute,
	}
	go rc.cleanup()
	return rc
}

func (rc *ReplayCache) IsSeen(jti string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	_, exists := rc.entries[jti]
	return exists
}

func (rc *ReplayCache) Mark(jti string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.entries[jti] = time.Now().Add(rc.ttl)
}

func (rc *ReplayCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		rc.mu.Lock()
		now := time.Now()
		for jti, expiry := range rc.entries {
			if now.After(expiry) {
				delete(rc.entries, jti)
			}
		}
		rc.mu.Unlock()
	}
}
