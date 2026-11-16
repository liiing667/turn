// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNonceHash(t *testing.T) {
	t.Run("generated hashes validate", func(t *testing.T) {
		h, err := NewNonceHash()
		assert.NoError(t, err)
		nonce, err := h.Generate()
		assert.NoError(t, err)
		assert.NoError(t, h.Validate(nonce))
	})

	t.Run("generated short hashes validate", func(t *testing.T) {
		for i := 1; i <= 8; i++ {
			h, err := NewShortNonceHash(i * 4)
			assert.NoError(t, err, fmt.Sprintf("nonce init at size %d", i*4))
			nonce, err := h.Generate()
			assert.NoError(t, err, fmt.Sprintf("generate at size %d", i*4))
			assert.NoError(t, h.Validate(nonce), fmt.Sprintf("decode at size %d", i*4))
		}
	})
}

func TestNonceValidationRules(t *testing.T) {
	t.Run("both implementations enforce the same rules", func(t *testing.T) {
		longHash, err := NewNonceHash()
		assert.NoError(t, err)
		shortHash, err := NewShortNonceHash(0)
		assert.NoError(t, err)

		now := time.Now()
		managers := map[string]NonceManager{
			"long":  longHash,
			"short": shortHash,
		}

		cases := []struct {
			name    string
			at      time.Time
			wantErr bool
		}{
			{"fresh nonce", now, false},
			{"nonce inside clock skew", now.Add(nonceClockSkew / 2), false},
			{"nonce inside lifetime", now.Add(-nonceLifetime / 2), false},
			{"nonce beyond clock skew", now.Add(nonceClockSkew + time.Minute), true},
			{"expired nonce", now.Add(-nonceLifetime - time.Minute), true},
		}

		for managerName, manager := range managers {
			for _, tc := range cases {
				var nonce string
				var err error
				switch m := manager.(type) {
				case *NonceHash:
					nonce, err = m.generateAt(tc.at)
				case *ShortNonceHash:
					nonce, err = m.generateAt(tc.at)
				default:
					t.Fatalf("unknown nonce manager %T", manager)
				}
				assert.NoError(t, err)

				if tc.wantErr {
					assert.ErrorIs(t, manager.Validate(nonce), errInvalidNonce,
						"%s/%s must be rejected", managerName, tc.name)
				} else {
					assert.NoError(t, manager.Validate(nonce),
						"%s/%s must be accepted", managerName, tc.name)
				}
			}
		}
	})

	t.Run("rejects nonces with an invalid signature", func(t *testing.T) {
		managers := map[string]NonceManager{}

		longHash, err := NewNonceHash()
		assert.NoError(t, err)
		managers["long"] = longHash

		shortHash, err := NewShortNonceHash(0)
		assert.NoError(t, err)
		managers["short"] = shortHash

		for name, manager := range managers {
			nonce, err := manager.Generate()
			assert.NoError(t, err)
			assert.ErrorIs(t, manager.Validate(tamperNonce(nonce)), errInvalidNonce,
				"%s nonce with a broken signature must be rejected", name)
		}
	})

	t.Run("rejects malformed nonces", func(t *testing.T) {
		managers := []NonceManager{}

		longHash, err := NewNonceHash()
		assert.NoError(t, err)
		managers = append(managers, longHash)

		shortHash, err := NewShortNonceHash(0)
		assert.NoError(t, err)
		managers = append(managers, shortHash)

		for _, manager := range managers {
			assert.ErrorIs(t, manager.Validate("not-a-nonce"), errInvalidNonce)
		}
	})
}

func tamperNonce(nonce string) string {
	last := nonce[len(nonce)-1]
	if last == '0' {
		return nonce[:len(nonce)-1] + "1"
	}

	return nonce[:len(nonce)-1] + "0"
}
