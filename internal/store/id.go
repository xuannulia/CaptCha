package store

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"
)

func newID(prefix string) string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw[:])
	}
	return prefix + "_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
}
