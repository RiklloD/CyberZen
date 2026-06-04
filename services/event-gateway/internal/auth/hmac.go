// Package auth provides shared signature verification helpers used by the
// per-provider webhook handlers.
package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

var (
	// ErrMissingSignature is returned when the provider did not supply the
	// signature header at all.
	ErrMissingSignature = errors.New("missing webhook signature")

	// ErrInvalidSignature is returned for malformed or mismatched signatures.
	ErrInvalidSignature = errors.New("invalid webhook signature")
)

// VerifyHMACSHA256 checks that signature equals HMAC-SHA256(body, secret),
// expressed as a hex string. Comparison is constant-time. A leading
// "sha256=" prefix (used by GitHub and others) is stripped automatically.
func VerifyHMACSHA256(secret string, body []byte, signature string) error {
	return verify(sha256.New, secret, body, signature, "sha256=")
}

// VerifyHMACSHA1 is the legacy GitHub format (X-Hub-Signature). Prefer
// VerifyHMACSHA256 when both are available.
func VerifyHMACSHA1(secret string, body []byte, signature string) error {
	return verify(sha1.New, secret, body, signature, "sha1=")
}

func verify(
	hasher func() hash.Hash,
	secret string,
	body []byte,
	signature string,
	prefix string,
) error {
	if signature == "" {
		return ErrMissingSignature
	}
	if secret == "" {
		// No secret configured — refuse rather than implicit-allow.
		return ErrInvalidSignature
	}

	signature = strings.TrimPrefix(signature, prefix)
	expected, err := hex.DecodeString(signature)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(hasher, []byte(secret))
	mac.Write(body)
	computed := mac.Sum(nil)

	if !hmac.Equal(expected, computed) {
		return ErrInvalidSignature
	}
	return nil
}
