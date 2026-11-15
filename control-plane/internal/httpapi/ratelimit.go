package httpapi

import (
	"crypto/sha256"
	"sync"
	"time"
)

const maxRateLimitSubjects = 100_000

type subjectBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type subjectLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[[32]byte]subjectBucket
	sweepAt time.Time
}

func newSubjectLimiter(rate float64, burst int) *subjectLimiter {
	return &subjectLimiter{rate: rate, burst: float64(burst), buckets: make(map[[32]byte]subjectBucket)}
}

func (l *subjectLimiter) allow(subject string) bool {
	key := sha256.Sum256([]byte(subject))
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.After(l.sweepAt) {
		for subject, bucket := range l.buckets {
			if now.Sub(bucket.lastSeen) > 10*time.Minute {
				delete(l.buckets, subject)
			}
		}
		l.sweepAt = now.Add(time.Minute)
	}
	bucket, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= maxRateLimitSubjects {
			return false
		}
		bucket = subjectBucket{tokens: l.burst, updated: now, lastSeen: now}
	}
	bucket.tokens += now.Sub(bucket.updated).Seconds() * l.rate
	if bucket.tokens > l.burst {
		bucket.tokens = l.burst
	}
	bucket.updated = now
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		l.buckets[key] = bucket
		return false
	}
	bucket.tokens--
	l.buckets[key] = bucket
	return true
}
