package store

import (
	"errors"
	"testing"
	"time"

	"captcha/internal/types"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisTransientStoreSessionTicketAndRate(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	store := NewRedisTransientStore(client, "test:")

	session := types.ChallengeSession{
		ID:        "sess_1",
		ClientID:  "demo",
		Scene:     "login",
		Type:      types.CaptchaSlider,
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
	}
	store.PutSession(session)
	loaded, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if loaded.ID != session.ID || loaded.Type != types.CaptchaSlider {
		t.Fatalf("unexpected session: %+v", loaded)
	}

	ticket := types.Ticket{
		Value:     "ticket_1",
		ClientID:  "demo",
		Scene:     "login",
		Route:     "/api/login",
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
	}
	store.PutTicket(ticket)

	verified, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "", false)
	if err != nil {
		t.Fatalf("verify ticket: %v", err)
	}
	if verified.Value != ticket.Value {
		t.Fatalf("unexpected ticket: %+v", verified)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "", "", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing route to reject bound ticket, got %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/other", "", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched route to reject bound ticket, got %v", err)
	}

	nonceTicket := types.Ticket{
		Value:        "ticket_nonce",
		ClientID:     "demo",
		Scene:        "login",
		Route:        "/api/login",
		RequestNonce: "nonce-1",
		ExpiresAt:    time.Now().Add(time.Minute),
		CreatedAt:    time.Now(),
	}
	store.PutTicket(nonceTicket)
	if _, err := store.VerifyTicket(nonceTicket.Value, "demo", "login", "/api/login", "nonce-1", "", "", false); err != nil {
		t.Fatalf("verify nonce ticket: %v", err)
	}
	if _, err := store.VerifyTicket(nonceTicket.Value, "demo", "login", "/api/login", "nonce-2", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched nonce to reject bound ticket, got %v", err)
	}
	contextTicket := types.Ticket{
		Value:         "ticket_context",
		ClientID:      "demo",
		Scene:         "login",
		Route:         "/api/login",
		IPHash:        "sha256:ip",
		UserAgentHash: "sha256:ua",
		ExpiresAt:     time.Now().Add(time.Minute),
		CreatedAt:     time.Now(),
	}
	store.PutTicket(contextTicket)
	if _, err := store.VerifyTicket(contextTicket.Value, "demo", "login", "/api/login", "", "sha256:ip", "sha256:ua", false); err != nil {
		t.Fatalf("verify context ticket: %v", err)
	}
	if _, err := store.VerifyTicket(contextTicket.Value, "demo", "login", "/api/login", "", "sha256:ip", "sha256:other", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched user agent hash to reject bound ticket, got %v", err)
	}

	clearance := types.Clearance{
		Value:         "clearance_1",
		ClientID:      "demo",
		Scene:         "login",
		IPHash:        "sha256:ip",
		UserAgentHash: "sha256:ua",
		AccountIDHash: "acct_hash",
		DeviceIDHash:  "device_hash",
		ExpiresAt:     time.Now().Add(time.Minute),
		CreatedAt:     time.Now(),
	}
	store.PutClearance(clearance)
	if _, err := store.VerifyClearance(clearance.Value, "demo", "login", "sha256:ip", "sha256:ua", "acct_hash", "device_hash"); err != nil {
		t.Fatalf("verify clearance: %v", err)
	}
	if _, err := store.VerifyClearance(clearance.Value, "demo", "login", "sha256:ip", "sha256:ua", "other_acct", "device_hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched account to reject clearance, got %v", err)
	}

	consumed, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "", true)
	if err != nil {
		t.Fatalf("consume ticket: %v", err)
	}
	if !consumed.Consumed {
		t.Fatal("expected consumed ticket")
	}

	_, err = store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "", false)
	if !errors.Is(err, ErrConsumed) {
		t.Fatalf("expected consumed error, got %v", err)
	}

	if got := store.IncrementRate("demo:route:ip", time.Minute, 5); got != 1 {
		t.Fatalf("rate 1 got %d", got)
	}
	if got := store.IncrementRate("demo:route:ip", time.Minute, 5); got != 2 {
		t.Fatalf("rate 2 got %d", got)
	}
}
