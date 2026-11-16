// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	nonceLifetime  = time.Hour // See: https://tools.ietf.org/html/rfc5766#section-4
	nonceClockSkew = time.Minute
	nonceLength    = 40
	nonceKeyLength = 64
)

// NewNonceHash creates a NonceHash.
func NewNonceHash() (NonceManager, error) {
	key := make([]byte, nonceKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return &NonceHash{key}, nil
}

// NonceHash is used to create and verify nonces.
type NonceHash struct {
	key []byte
}

// Generate a nonce.
func (n *NonceHash) Generate() (string, error) {
	return n.generateAt(time.Now())
}

func (n *NonceHash) generateAt(now time.Time) (string, error) {
	nonce := make([]byte, 8, nonceLength)
	binary.BigEndian.PutUint64(nonce, uint64(now.UnixMilli())) // nolint:gosec // G115

	hash := hmac.New(sha256.New, n.key)
	if _, err := hash.Write(nonce[:8]); err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToGenerateNonce, err) //nolint:errorlint
	}
	nonce = hash.Sum(nonce)

	return hex.EncodeToString(nonce), nil
}

// Validate checks that nonce is signed, is not from the future beyond the
// allowed clock skew and is not expired.
func (n *NonceHash) Validate(nonce string) error {
	b, err := hex.DecodeString(nonce)
	if err != nil || len(b) != nonceLength {
		return fmt.Errorf("%w: %v", errInvalidNonce, err) //nolint:errorlint
	}

	ts := time.UnixMilli(int64(binary.BigEndian.Uint64(b))) // nolint:gosec // G115
	if time.Until(ts) > nonceClockSkew {
		return errInvalidNonce
	}

	if time.Since(ts) > nonceLifetime {
		return errInvalidNonce
	}

	hash := hmac.New(sha256.New, n.key)
	if _, err = hash.Write(b[:8]); err != nil {
		return fmt.Errorf("%w: %v", errInvalidNonce, err) //nolint:errorlint
	}
	if !hmac.Equal(b[8:], hash.Sum(nil)) {
		return errInvalidNonce
	}

	return nil
}
