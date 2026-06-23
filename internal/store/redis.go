package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"captcha/internal/types"

	"github.com/redis/go-redis/v9"
)

type RedisTransientStore struct {
	client *redis.Client
	prefix string
}

func NewRedisTransientStore(client *redis.Client, prefix string) *RedisTransientStore {
	if prefix == "" {
		prefix = "captcha:"
	}
	return &RedisTransientStore{client: client, prefix: prefix}
}

func (s *RedisTransientStore) PutSession(session types.ChallengeSession) {
	_ = s.setJSON(context.Background(), s.sessionKey(session.ID), session, ttlUntil(session.ExpiresAt))
}

func (s *RedisTransientStore) GetSession(id string) (types.ChallengeSession, error) {
	var session types.ChallengeSession
	if err := s.getJSON(context.Background(), s.sessionKey(id), &session); err != nil {
		return types.ChallengeSession{}, err
	}
	if time.Now().After(session.ExpiresAt) {
		return types.ChallengeSession{}, ErrExpired
	}
	return session, nil
}

func (s *RedisTransientStore) UpdateSession(session types.ChallengeSession) {
	s.PutSession(session)
}

func (s *RedisTransientStore) PutTicket(ticket types.Ticket) {
	_ = s.setJSON(context.Background(), s.ticketKey(ticket.Value), ticket, ttlUntil(ticket.ExpiresAt))
}

func (s *RedisTransientStore) PutClearance(clearance types.Clearance) {
	_ = s.setJSON(context.Background(), s.clearanceKey(clearance.Value), clearance, ttlUntil(clearance.ExpiresAt))
}

func (s *RedisTransientStore) VerifyClearance(value, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) (types.Clearance, error) {
	var clearance types.Clearance
	key := s.clearanceKey(value)
	if err := s.getJSON(context.Background(), key, &clearance); err != nil {
		return types.Clearance{}, err
	}
	if err := validateClearance(clearance, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash); err != nil {
		if errors.Is(err, ErrExpired) {
			_ = s.client.Del(context.Background(), key).Err()
		}
		return types.Clearance{}, err
	}
	return clearance, nil
}

func (s *RedisTransientStore) VerifyTicket(value, clientID, scene, route, requestNonce, ipHash, userAgentHash string, consume bool) (types.Ticket, error) {
	ctx := context.Background()
	key := s.ticketKey(value)
	if !consume {
		ticket, err := s.getTicket(ctx, key)
		if err != nil {
			return types.Ticket{}, err
		}
		if err := validateTicket(ticket, clientID, scene, route, requestNonce, ipHash, userAgentHash); err != nil {
			return types.Ticket{}, err
		}
		return ticket, nil
	}

	var consumed types.Ticket
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		ticket, err := s.getTicketFromClient(ctx, tx, key)
		if err != nil {
			return err
		}
		if err := validateTicket(ticket, clientID, scene, route, requestNonce, ipHash, userAgentHash); err != nil {
			return err
		}
		now := time.Now()
		ticket.Consumed = true
		ticket.ConsumedAt = &now
		data, err := json.Marshal(ticket)
		if err != nil {
			return err
		}
		ttl := ttlUntil(ticket.ExpiresAt)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, data, ttl)
			return nil
		})
		if err != nil {
			return err
		}
		consumed = ticket
		return nil
	}, key)
	if errors.Is(err, redis.TxFailedErr) {
		return types.Ticket{}, ErrConsumed
	}
	if err != nil {
		return types.Ticket{}, err
	}
	return consumed, nil
}

func (s *RedisTransientStore) IncrementRate(key string, window time.Duration, maxRequests int, strategy ...string) int {
	ctx := context.Background()
	redisKey := s.rateKey(key)
	switch rateStrategy(strategy...) {
	case "sliding_window":
		now := time.Now()
		nowMS := now.UnixMilli()
		minScore := now.Add(-window).UnixMilli()
		member := fmt.Sprintf("%d:%d", nowMS, now.UnixNano())
		pipe := s.client.Pipeline()
		pipe.ZRemRangeByScore(ctx, redisKey, "-inf", fmt.Sprintf("%d", minScore))
		pipe.ZAdd(ctx, redisKey, redis.Z{Score: float64(nowMS), Member: member})
		countCmd := pipe.ZCard(ctx, redisKey)
		if window > 0 {
			pipe.Expire(ctx, redisKey, window)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return 1
		}
		return int(countCmd.Val())
	case "token_bucket":
		return s.incrementTokenBucketRate(ctx, redisKey, window, maxRequests)
	}
	count, err := s.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return 1
	}
	if count == 1 && window > 0 {
		_ = s.client.Expire(ctx, redisKey, window).Err()
	}
	return int(count)
}

func (s *RedisTransientStore) incrementTokenBucketRate(ctx context.Context, key string, window time.Duration, maxRequests int) int {
	if maxRequests <= 0 || window <= 0 {
		return 1
	}
	capacity := float64(maxRequests)
	for attempt := 0; attempt < 3; attempt++ {
		now := time.Now()
		var result int
		err := s.client.Watch(ctx, func(tx *redis.Tx) error {
			values, err := tx.HMGet(ctx, key, "tokens", "last_refill").Result()
			if err != nil {
				return err
			}
			tokens := capacity
			lastRefill := now
			if len(values) > 0 && values[0] != nil {
				tokens = redisFloat(values[0], capacity)
			}
			if len(values) > 1 && values[1] != nil {
				lastRefill = time.Unix(0, redisInt64(values[1], now.UnixNano()))
			}
			if elapsed := now.Sub(lastRefill); elapsed > 0 {
				refill := elapsed.Seconds() * capacity / window.Seconds()
				tokens = math.Min(capacity, tokens+refill)
			}
			if tokens < 1 {
				result = maxRequests + 1
			} else {
				tokens--
				result = int(math.Ceil(capacity - tokens))
				if result < 1 {
					result = 1
				}
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, key, "tokens", tokens, "last_refill", now.UnixNano())
				pipe.Expire(ctx, key, tokenBucketTTL(window))
				return nil
			})
			return err
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			if strings.Contains(err.Error(), "WRONGTYPE") {
				_ = s.client.Del(ctx, key).Err()
				continue
			}
			return 1
		}
		return result
	}
	return 1
}

func tokenBucketTTL(window time.Duration) time.Duration {
	ttl := 2 * window
	if ttl < time.Second {
		return time.Second
	}
	return ttl
}

func redisFloat(value any, fallback float64) float64 {
	parsed, err := strconv.ParseFloat(fmt.Sprint(value), 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func redisInt64(value any, fallback int64) int64 {
	parsed, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func (s *RedisTransientStore) setJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, data, ttl).Err()
}

func (s *RedisTransientStore) getJSON(ctx context.Context, key string, out any) error {
	data, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (s *RedisTransientStore) getTicket(ctx context.Context, key string) (types.Ticket, error) {
	return s.getTicketFromClient(ctx, s.client, key)
}

type redisGetter interface {
	Get(context.Context, string) *redis.StringCmd
}

func (s *RedisTransientStore) getTicketFromClient(ctx context.Context, client redisGetter, key string) (types.Ticket, error) {
	var ticket types.Ticket
	data, err := client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return types.Ticket{}, ErrNotFound
	}
	if err != nil {
		return types.Ticket{}, err
	}
	if err := json.Unmarshal(data, &ticket); err != nil {
		return types.Ticket{}, err
	}
	return ticket, nil
}

func validateTicket(ticket types.Ticket, clientID, scene, route, requestNonce, ipHash, userAgentHash string) error {
	if time.Now().After(ticket.ExpiresAt) {
		return ErrExpired
	}
	if ticket.Consumed {
		return ErrConsumed
	}
	if ticket.ClientID != clientID || ticket.Scene != scene {
		return ErrNotFound
	}
	if ticket.Route != "" && ticket.Route != route {
		return ErrNotFound
	}
	if ticket.RequestNonce != "" && ticket.RequestNonce != requestNonce {
		return ErrNotFound
	}
	if ticket.IPHash != "" && ticket.IPHash != ipHash {
		return ErrNotFound
	}
	if ticket.UserAgentHash != "" && ticket.UserAgentHash != userAgentHash {
		return ErrNotFound
	}
	return nil
}

func validateClearance(clearance types.Clearance, clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) error {
	if time.Now().After(clearance.ExpiresAt) {
		return ErrExpired
	}
	if clearance.ClientID != clientID || clearance.Scene != scene {
		return ErrNotFound
	}
	if clearance.IPHash != "" && clearance.IPHash != ipHash {
		return ErrNotFound
	}
	if clearance.UserAgentHash != "" && clearance.UserAgentHash != userAgentHash {
		return ErrNotFound
	}
	if clearance.AccountIDHash != "" && clearance.AccountIDHash != accountIDHash {
		return ErrNotFound
	}
	if clearance.DeviceIDHash != "" && clearance.DeviceIDHash != deviceIDHash {
		return ErrNotFound
	}
	return nil
}

func ttlUntil(expiresAt time.Time) time.Duration {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return time.Millisecond
	}
	return ttl
}

func (s *RedisTransientStore) sessionKey(id string) string {
	return s.prefix + "session:" + id
}

func (s *RedisTransientStore) ticketKey(value string) string {
	return s.prefix + "ticket:" + value
}

func (s *RedisTransientStore) clearanceKey(value string) string {
	return s.prefix + "clearance:" + value
}

func (s *RedisTransientStore) rateKey(key string) string {
	return s.prefix + "rate:" + key
}

var _ SessionStore = (*RedisTransientStore)(nil)
var _ TicketStore = (*RedisTransientStore)(nil)
var _ ClearanceStore = (*RedisTransientStore)(nil)
var _ RateStore = (*RedisTransientStore)(nil)
