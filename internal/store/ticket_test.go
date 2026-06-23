package store

import (
	"errors"
	"testing"
	"time"

	"captcha/internal/types"
)

func TestMemoryStoreTicketRequiresBoundRoute(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ticket := types.Ticket{
		Value:     "ticket_route_bound",
		ClientID:  "demo",
		Scene:     "login",
		Route:     "/api/login",
		ExpiresAt: time.Now().Add(time.Minute),
		CreatedAt: time.Now(),
	}
	store.PutTicket(ticket)

	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "", false); err != nil {
		t.Fatalf("expected ticket to verify for bound route: %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "", "", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing route to reject bound ticket, got %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/other", "", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched route to reject bound ticket, got %v", err)
	}
}

func TestMemoryStoreTicketRequiresBoundRequestNonce(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ticket := types.Ticket{
		Value:        "ticket_nonce_bound",
		ClientID:     "demo",
		Scene:        "login",
		Route:        "/api/login",
		RequestNonce: "nonce-1",
		ExpiresAt:    time.Now().Add(time.Minute),
		CreatedAt:    time.Now(),
	}
	store.PutTicket(ticket)

	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "nonce-1", "", "", false); err != nil {
		t.Fatalf("expected ticket to verify for bound nonce: %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing nonce to reject bound ticket, got %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "nonce-2", "", "", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched nonce to reject bound ticket, got %v", err)
	}
}

func TestMemoryStoreTicketRequiresBoundIPAndUserAgent(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ticket := types.Ticket{
		Value:         "ticket_context_bound",
		ClientID:      "demo",
		Scene:         "login",
		Route:         "/api/login",
		IPHash:        "sha256:ip",
		UserAgentHash: "sha256:ua",
		ExpiresAt:     time.Now().Add(time.Minute),
		CreatedAt:     time.Now(),
	}
	store.PutTicket(ticket)

	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "sha256:ip", "sha256:ua", false); err != nil {
		t.Fatalf("expected context-bound ticket to verify: %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "", "sha256:ua", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing ip hash to reject bound ticket, got %v", err)
	}
	if _, err := store.VerifyTicket(ticket.Value, "demo", "login", "/api/login", "", "sha256:ip", "sha256:other", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched user agent hash to reject bound ticket, got %v", err)
	}
}

func TestMemoryStoreClearanceRequiresBoundContext(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	clearance := types.Clearance{
		Value:         "clearance_context_bound",
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
		t.Fatalf("expected context-bound clearance to verify: %v", err)
	}
	if _, err := store.VerifyClearance(clearance.Value, "demo", "login", "sha256:ip", "sha256:ua", "other_acct", "device_hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched account hash to reject clearance, got %v", err)
	}
	if _, err := store.VerifyClearance(clearance.Value, "demo", "login", "sha256:ip", "sha256:ua", "acct_hash", "other_device"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected mismatched device hash to reject clearance, got %v", err)
	}
}
