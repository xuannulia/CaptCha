package secret

import (
	"strings"
	"testing"
)

func TestClientSecretHashAndVerify(t *testing.T) {
	t.Parallel()

	value, hash, err := NewClientSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	if !strings.HasPrefix(value, "cap_secret_") {
		t.Fatalf("unexpected secret prefix: %q", value)
	}
	if strings.Contains(hash, value) {
		t.Fatal("hash must not contain the plain secret")
	}
	if !VerifyClientSecret(hash, value) {
		t.Fatal("expected generated secret to verify")
	}
	if VerifyClientSecret(hash, value+"x") {
		t.Fatal("expected changed secret to fail verification")
	}
}
