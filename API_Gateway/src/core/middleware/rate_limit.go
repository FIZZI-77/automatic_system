package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	Name       string
	Limit      int
	Burst      int
	Window     time.Duration
	KeyFunc    func(*gin.Context) string
	SkipFunc   func(*gin.Context) bool
	RetryAfter time.Duration
}

type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*rateBucket
	limit       int
	burst       int
	window      time.Duration
	lastCleanup time.Time
}

type rateBucket struct {
	limiter    *rate.Limiter
	lastSeenAt time.Time
}

func RateLimit(config RateLimitConfig) gin.HandlerFunc {
	if config.Window <= 0 {
		config.Window = time.Minute
	}
	if config.Limit <= 0 {
		config.Limit = 60
	}
	if config.Burst <= 0 {
		config.Burst = config.Limit
	}
	if config.RetryAfter <= 0 {
		config.RetryAfter = time.Second
	}
	if config.KeyFunc == nil {
		config.KeyFunc = func(c *gin.Context) string {
			return c.ClientIP()
		}
	}

	limiter := &rateLimiter{
		buckets:     make(map[string]*rateBucket),
		limit:       config.Limit,
		burst:       config.Burst,
		window:      config.Window,
		lastCleanup: time.Now(),
	}

	return func(c *gin.Context) {
		if config.SkipFunc != nil && config.SkipFunc(c) {
			c.Next()
			return
		}

		key := config.Name + ":" + config.KeyFunc(c)
		allowed, remaining, retryAfter := limiter.allow(key, time.Now(), config.RetryAfter)
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if !allowed {
			c.Header("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

func (l *rateLimiter) allow(key string, now time.Time, defaultRetryAfter time.Duration) (bool, int, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanup(now)

	bucket, ok := l.buckets[key]
	if !ok {
		bucket = &rateBucket{
			limiter:    rate.NewLimiter(rate.Every(l.window/time.Duration(l.limit)), l.burst),
			lastSeenAt: now,
		}
		l.buckets[key] = bucket
	}

	bucket.lastSeenAt = now

	if bucket.limiter.AllowN(now, 1) {
		return true, int(bucket.limiter.Tokens()), 0
	}

	reservation := bucket.limiter.ReserveN(now, 1)
	if !reservation.OK() {
		return false, 0, defaultRetryAfter
	}
	retryAfter := reservation.DelayFrom(now)
	reservation.CancelAt(now)

	if retryAfter <= 0 {
		retryAfter = defaultRetryAfter
	}
	if retryAfter%time.Second != 0 {
		retryAfter = retryAfter.Truncate(time.Second) + time.Second
	}

	return false, 0, retryAfter
}

func (l *rateLimiter) cleanup(now time.Time) {
	if now.Sub(l.lastCleanup) < time.Minute {
		return
	}

	expireBefore := now.Add(-5 * time.Minute)
	for key, bucket := range l.buckets {
		if bucket.lastSeenAt.Before(expireBefore) {
			delete(l.buckets, key)
		}
	}

	l.lastCleanup = now
}
