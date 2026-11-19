// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package server

import (
	"net"
	"testing"
	"time"

	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
)

type fakeAddr struct {
	network, address string
}

func (f fakeAddr) Network() string { return f.network }
func (f fakeAddr) String() string  { return f.address }

type fakePacketConn struct {
	local net.Addr
}

func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (f *fakePacketConn) Close() error                           { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                    { return f.local }
func (f *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }

func TestDefaultAllocationAddressFamilyClassification(t *testing.T) {
	t.Run("IPv4 listener", func(t *testing.T) {
		req := Request{
			Conn: &fakePacketConn{local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478}},
		}
		family, err := defaultAllocationAddressFamily(req)
		assert.NoError(t, err)
		assert.Equal(t, proto.RequestedFamilyIPv4, family)
	})

	t.Run("IPv6 listener", func(t *testing.T) {
		req := Request{
			Conn: &fakePacketConn{local: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 3478}},
		}
		family, err := defaultAllocationAddressFamily(req)
		assert.NoError(t, err)
		assert.Equal(t, proto.RequestedFamilyIPv6, family)
	})

	t.Run("wildcard listener uses client family", func(t *testing.T) {
		req := Request{
			Conn:    &fakePacketConn{local: &net.UDPAddr{IP: net.IPv6unspecified, Port: 3478}},
			SrcAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 5000},
		}
		family, err := defaultAllocationAddressFamily(req)
		assert.NoError(t, err)
		assert.Equal(t, proto.RequestedFamilyIPv4, family)
	})

	t.Run("strict mode always IPv4", func(t *testing.T) {
		req := Request{
			Conn:                &fakePacketConn{local: fakeAddr{}},
			StrictAddressFamily: true,
		}
		family, err := defaultAllocationAddressFamily(req)
		assert.NoError(t, err)
		assert.Equal(t, proto.RequestedFamilyIPv4, family)
	})

	t.Run("unclassifiable listener fails", func(t *testing.T) {
		req := Request{
			Conn: &fakePacketConn{local: fakeAddr{network: "udp", address: "unknown"}},
		}
		_, err := defaultAllocationAddressFamily(req)
		assert.ErrorIs(t, err, errUnsupportedAddressFamily)
	})

	t.Run("wildcard with unclassifiable client fails", func(t *testing.T) {
		req := Request{
			Conn:    &fakePacketConn{local: &net.UDPAddr{IP: net.IPv6unspecified, Port: 3478}},
			SrcAddr: fakeAddr{network: "udp", address: "unknown"},
		}
		_, err := defaultAllocationAddressFamily(req)
		assert.ErrorIs(t, err, errUnsupportedAddressFamily)
	})
}
