package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	hashAlgorithm = "pbkdf2_sha256"
	iterations    = 120_000
	saltBytes     = 16
	keyBytes      = 32
)

func NewClientSecret() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	value := "cap_secret_" + base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashClientSecret(value)
	if err != nil {
		return "", "", err
	}
	return value, hash, nil
}

func HashClientSecret(value string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(value), salt, iterations, keyBytes)
	return fmt.Sprintf(
		"%s$%d$%s$%s",
		hashAlgorithm,
		iterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	), nil
}

func VerifyClientSecret(hash, value string) bool {
	if hash == "" || value == "" {
		return false
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != hashAlgorithm {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2SHA256([]byte(value), salt, iter, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var blockIndex [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(blockIndex[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
