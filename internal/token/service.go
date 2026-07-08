package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"captcha/internal/store"
	"captcha/internal/types"
)

type Service struct {
	store        store.TicketStore
	clearances   store.ClearanceStore
	ttl          time.Duration
	clearanceTTL time.Duration
}

const defaultClearanceTTL = 10 * time.Minute

func NewService(ticketStore store.TicketStore, ttl time.Duration) *Service {
	clearances, _ := ticketStore.(store.ClearanceStore)
	return &Service{store: ticketStore, clearances: clearances, ttl: ttl, clearanceTTL: defaultClearanceTTL}
}

func (s *Service) SetClearanceTTL(ttl time.Duration) {
	if ttl > 0 {
		s.clearanceTTL = ttl
	}
}

func (s *Service) Issue(clientID, scene, route, requestNonce, ipHash, userAgentHash string, subjectHashes ...string) (types.Ticket, error) {
	value, err := randomID("cap_ticket_", 32)
	if err != nil {
		return types.Ticket{}, err
	}
	accountIDHash := ""
	deviceIDHash := ""
	if len(subjectHashes) > 0 {
		accountIDHash = subjectHashes[0]
	}
	if len(subjectHashes) > 1 {
		deviceIDHash = subjectHashes[1]
	}
	now := time.Now()
	ticket := types.Ticket{
		Value:         value,
		ClientID:      clientID,
		Scene:         scene,
		Route:         route,
		RequestNonce:  requestNonce,
		IPHash:        ipHash,
		UserAgentHash: userAgentHash,
		AccountIDHash: accountIDHash,
		DeviceIDHash:  deviceIDHash,
		ExpiresAt:     now.Add(s.ttl),
		CreatedAt:     now,
	}
	s.store.PutTicket(ticket)
	return ticket, nil
}

func (s *Service) IssueClearance(clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string) (types.Clearance, error) {
	return s.IssueClearanceWithTTL(clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash, 0)
}

func (s *Service) IssueClearanceWithTTL(clientID, scene, ipHash, userAgentHash, accountIDHash, deviceIDHash string, ttl time.Duration) (types.Clearance, error) {
	if s.clearances == nil {
		return types.Clearance{}, errors.New("clearance store is unavailable")
	}
	if ttl <= 0 {
		ttl = s.clearanceTTL
	}
	value, err := randomID("cap_clearance_", 32)
	if err != nil {
		return types.Clearance{}, err
	}
	now := time.Now()
	clearance := types.Clearance{
		Value:         value,
		ClientID:      clientID,
		Scene:         scene,
		IPHash:        ipHash,
		UserAgentHash: userAgentHash,
		AccountIDHash: accountIDHash,
		DeviceIDHash:  deviceIDHash,
		ExpiresAt:     now.Add(ttl),
		CreatedAt:     now,
	}
	s.clearances.PutClearance(clearance)
	return clearance, nil
}

func randomID(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
