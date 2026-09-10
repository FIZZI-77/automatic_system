package middleware

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const rateLimitScript = `
local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated_at')
local tokens = tonumber(values[1]) or tonumber(ARGV[2])
local updated_at = tonumber(values[2]) or tonumber(ARGV[1])
local now = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local refill_per_ms = tonumber(ARGV[3])

tokens = math.min(burst, tokens + math.max(0, now - updated_at) * refill_per_ms)
local allowed = 0
local retry_after_ms = 0

if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_after_ms = math.ceil((1 - tokens) / refill_per_ms)
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated_at', now)
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return {allowed, math.floor(tokens), retry_after_ms}
`

type RateLimitConfig struct {
	Name     string
	Limit    int
	Burst    int
	Window   time.Duration
	KeyFunc  func(*gin.Context) string
	SkipFunc func(*gin.Context) bool
}

type RedisRateLimiter struct {
	client          redis.UniversalClient
	script          *redis.Script
	prefix          string
	bypassLoadTests bool
}

func NewRedisRateLimiter(client redis.UniversalClient, prefix string, bypassLoadTests bool) *RedisRateLimiter {
	return &RedisRateLimiter{
		client:          client,
		script:          redis.NewScript(rateLimitScript),
		prefix:          prefix,
		bypassLoadTests: bypassLoadTests,
	}
}

func (l *RedisRateLimiter) Middleware(config RateLimitConfig) gin.HandlerFunc {
	config.normalize()

	return func(c *gin.Context) {
		if l.bypassLoadTests && c.GetHeader("X-Load-Test-Run-ID") != "" {
			c.Next()
			return
		}

		if config.SkipFunc != nil && config.SkipFunc(c) {
			c.Next()
			return
		}

		key := fmt.Sprintf("%s:%s:%s", l.prefix, config.Name, config.KeyFunc(c))
		allowed, remaining, retryAfter, err := l.allow(c.Request.Context(), key, config)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "rate limiter unavailable"})
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(config.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}

func (l *RedisRateLimiter) allow(ctx context.Context, key string, config RateLimitConfig) (bool, int, time.Duration, error) {
	refillPerMillisecond := float64(config.Limit) / float64(config.Window.Milliseconds())
	ttl := max(config.Window*time.Duration(config.Burst/config.Limit+1), config.Window)

	result, err := l.script.Run(ctx, l.client, []string{key},
		time.Now().UnixMilli(), config.Burst, refillPerMillisecond, ttl.Milliseconds(),
	).Slice()
	if err != nil {
		return false, 0, 0, fmt.Errorf("redis rate limiter: %w", err)
	}
	if len(result) != 3 {
		return false, 0, 0, fmt.Errorf("redis rate limiter: unexpected result")
	}

	allowed, err := redisInt(result[0])
	if err != nil {
		return false, 0, 0, err
	}
	remaining, err := redisInt(result[1])
	if err != nil {
		return false, 0, 0, err
	}
	retryAfter, err := redisInt(result[2])
	if err != nil {
		return false, 0, 0, err
	}
	return allowed == 1, int(remaining), time.Duration(retryAfter) * time.Millisecond, nil
}

func (c *RateLimitConfig) normalize() {
	if c.Window <= 0 {
		c.Window = time.Minute
	}
	if c.Limit <= 0 {
		c.Limit = 60
	}
	if c.Burst <= 0 {
		c.Burst = c.Limit
	}
	if c.KeyFunc == nil {
		c.KeyFunc = func(ctx *gin.Context) string { return ctx.ClientIP() }
	}
}

func redisInt(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		return strconv.ParseInt(typed, 10, 64)
	default:
		return 0, fmt.Errorf("redis rate limiter: unexpected value %T", value)
	}
}
