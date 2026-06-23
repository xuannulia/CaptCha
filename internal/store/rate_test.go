package store

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMemoryStoreSlidingWindowRatePrunesExpiredHits(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	window := time.Minute
	now := time.Now()
	store.rateCounters["rate:sliding"] = rateCounter{
		Hits: []time.Time{
			now.Add(-2 * window),
			now.Add(-window / 2),
		},
	}

	if got := store.IncrementRate("rate:sliding", window, 5, "sliding_window"); got != 2 {
		t.Fatalf("expected one recent hit plus current hit, got %d", got)
	}
	counter := store.rateCounters["rate:sliding"]
	if len(counter.Hits) != 2 {
		t.Fatalf("expected expired hit to be pruned, got %+v", counter.Hits)
	}
}

func TestMemoryStoreTokenBucketRateRefillsOverWindow(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	key := "rate:token"
	window := time.Minute
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 1 {
		t.Fatalf("expected first token bucket hit to pass, got %d", got)
	}
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 2 {
		t.Fatalf("expected second token bucket hit to pass, got %d", got)
	}
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 3 {
		t.Fatalf("expected empty token bucket to exceed limit, got %d", got)
	}

	store.mu.Lock()
	counter := store.rateCounters[key]
	counter.Tokens = 0
	counter.LastRefill = time.Now().Add(-window)
	store.rateCounters[key] = counter
	store.mu.Unlock()
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 1 {
		t.Fatalf("expected token bucket to refill after window, got %d", got)
	}
}

func TestRedisTransientStoreSlidingWindowRatePrunesExpiredHits(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	store := NewRedisTransientStore(client, "test:")
	ctx := t.Context()
	key := store.rateKey("rate:sliding")
	now := time.Now()
	window := time.Minute
	if err := client.ZAdd(ctx, key,
		redis.Z{Score: float64(now.Add(-2 * window).UnixMilli()), Member: "expired"},
		redis.Z{Score: float64(now.Add(-window / 2).UnixMilli()), Member: "recent"},
	).Err(); err != nil {
		t.Fatalf("seed sorted set: %v", err)
	}

	if got := store.IncrementRate("rate:sliding", window, 5, "sliding_window"); got != 2 {
		t.Fatalf("expected one recent hit plus current hit, got %d", got)
	}
	if count := client.ZCard(ctx, key).Val(); count != 2 {
		t.Fatalf("expected expired redis hit to be pruned, got %d", count)
	}
}

func TestRedisTransientStoreTokenBucketRateRefillsOverWindow(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	store := NewRedisTransientStore(client, "test:")
	ctx := t.Context()
	key := "rate:token"
	window := time.Minute
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 1 {
		t.Fatalf("expected first token bucket hit to pass, got %d", got)
	}
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 2 {
		t.Fatalf("expected second token bucket hit to pass, got %d", got)
	}
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 3 {
		t.Fatalf("expected empty token bucket to exceed limit, got %d", got)
	}

	if err := client.HSet(ctx, store.rateKey(key), "tokens", 0, "last_refill", time.Now().Add(-window).UnixNano()).Err(); err != nil {
		t.Fatalf("rewind token bucket: %v", err)
	}
	if got := store.IncrementRate(key, window, 2, "token_bucket"); got != 1 {
		t.Fatalf("expected token bucket to refill after window, got %d", got)
	}
}
