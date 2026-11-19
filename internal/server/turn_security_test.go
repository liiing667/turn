// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package server

import (
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5/internal/allocation"
	"github.com/pion/turn/v5/internal/auth"
	"github.com/pion/turn/v5/internal/proto"
	"github.com/stretchr/testify/assert"
)

// newSecurityTestManager builds an AllocationManager whose AllocateConn
// callback fails the test if invoked: a successful bypass would dial a peer
// the family or permission rules should have rejected.
func newSecurityTestManager(t *testing.T) *allocation.Manager {
	t.Helper()

	manager, err := allocation.NewManager(allocation.ManagerConfig{
		AllocatePacketConn: func(conf allocation.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			con, listenErr := net.ListenPacket(conf.Network, "127.0.0.1:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return con, con.LocalAddr(), nil
		},
		AllocateListener: func(allocation.AllocateListenerConfig) (net.Listener, net.Addr, error) {
			return nil, nil, nil //nolint:nilnil
		},
		AllocateConn: func(allocation.AllocateConnConfig) (net.Conn, error) {
			t.Errorf("AllocateConn must never be called for an unauthorized or cross-family peer")

			return nil, net.ErrClosed
		},
		LeveledLogger: &captureLogger{},
	})
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, manager.Close()) })

	return manager
}

func newSecurityRequest(t *testing.T, manager *allocation.Manager) (Request, []byte) {
	t.Helper()

	nonceHash, err := NewShortNonceHash(0)
	assert.NoError(t, err)
	staticKey, err := nonceHash.Generate()
	assert.NoError(t, err)

	conn := newCapturePacketConn(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478})
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	req := Request{
		AllocationManager: manager,
		NonceHash:         nonceHash,
		Conn:              conn,
		SrcAddr:           &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
		Log:               &captureLogger{},
		AuthHandler: func(*auth.RequestAttributes) (string, []byte, bool) {
			return testUser, []byte(staticKey), true
		},
	}

	return req, []byte(staticKey)
}

func authenticatedConnectMsg(t *testing.T, staticKey []byte, peer proto.PeerAddress) *stun.Message {
	t.Helper()

	m := &stun.Message{}
	m.TransactionID = stun.NewTransactionID()
	assert.NoError(t, m.Build(stun.NewType(stun.MethodConnect, stun.ClassRequest)))
	assert.NoError(t, (proto.Lifetime{}).AddTo(m))
	assert.NoError(t, (stun.MessageIntegrity(staticKey)).AddTo(m))
	assert.NoError(t, (stun.Nonce(staticKey)).AddTo(m))
	assert.NoError(t, (stun.Realm(staticKey)).AddTo(m))
	assert.NoError(t, (stun.Username(testUser)).AddTo(m))
	assert.NoError(t, peer.AddTo(m))

	return m
}

// TestSecurityConnectCrossFamilyRejected proves that an RFC 6062 Connect
// request to a peer whose address family does not match the allocation's
// relayed address family is rejected with 443 and never reaches the dialer.
func TestSecurityConnectCrossFamilyRejected(t *testing.T) {
	manager := newSecurityTestManager(t)
	req, staticKey := newSecurityRequest(t, manager)

	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}
	_, err := manager.CreateAllocation(fiveTuple, req.Conn, proto.ProtoUDP,
		0, time.Hour, testUser, "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)

	msg := authenticatedConnectMsg(t, staticKey, proto.PeerAddress{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 9,
	})

	err = handleConnectRequest(req, msg)
	assert.ErrorIs(t, err, errPeerAddressFamilyMismatch)
	assertLastErrorCode(t, req.Conn, stun.MethodConnect, stun.CodePeerAddrFamilyMismatch)
}

// TestSecurityConnectCrossFamilySkipsPermissionHandler proves the family
// check runs before authorization: a cross-family peer must never reach the
// PermissionHandler, so a policy cannot be probed or widened through it.
func TestSecurityConnectCrossFamilySkipsPermissionHandler(t *testing.T) {
	logger := &captureLogger{}
	permissionChecked := false
	manager, err := allocation.NewManager(allocation.ManagerConfig{
		AllocatePacketConn: func(conf allocation.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			con, listenErr := net.ListenPacket(conf.Network, "127.0.0.1:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return con, con.LocalAddr(), nil
		},
		AllocateListener: func(allocation.AllocateListenerConfig) (net.Listener, net.Addr, error) {
			return nil, nil, nil //nolint:nilnil
		},
		AllocateConn: func(allocation.AllocateConnConfig) (net.Conn, error) {
			t.Fatal("AllocateConn must not be called for a cross-family peer")

			return nil, net.ErrClosed
		},
		PermissionHandler: func(net.Addr, net.IP) bool {
			permissionChecked = true

			return true
		},
		LeveledLogger: logger,
	})
	assert.NoError(t, err)
	defer manager.Close() //nolint:errcheck

	req, staticKey := newSecurityRequest(t, manager)
	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}
	_, err = manager.CreateAllocation(fiveTuple, req.Conn, proto.ProtoUDP,
		0, time.Hour, testUser, "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)

	msg := authenticatedConnectMsg(t, staticKey, proto.PeerAddress{
		IP:   net.ParseIP("2001:db8::2"),
		Port: 9,
	})
	err = handleConnectRequest(req, msg)
	assert.ErrorIs(t, err, errPeerAddressFamilyMismatch)
	assert.False(t, permissionChecked, "PermissionHandler must not run for a cross-family peer")
	assertLastErrorCode(t, req.Conn, stun.MethodConnect, stun.CodePeerAddrFamilyMismatch)
}

// TestSecurityConnectSameFamilyPermitted guards against over-rejection: a
// same-family Connect request must still reach the dialer path.
func TestSecurityConnectSameFamilyPermitted(t *testing.T) {
	dialed := make(chan struct{}, 1)
	manager, err := allocation.NewManager(allocation.ManagerConfig{
		AllocatePacketConn: func(conf allocation.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			con, listenErr := net.ListenPacket(conf.Network, "127.0.0.1:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return con, con.LocalAddr(), nil
		},
		AllocateListener: func(allocation.AllocateListenerConfig) (net.Listener, net.Addr, error) {
			return nil, nil, nil //nolint:nilnil
		},
		AllocateConn: func(allocation.AllocateConnConfig) (net.Conn, error) {
			close(dialed)

			return nil, allocation.ErrTCPConnectionTimeoutOrFailure
		},
		LeveledLogger: &captureLogger{},
	})
	assert.NoError(t, err)
	defer manager.Close() //nolint:errcheck

	req, staticKey := newSecurityRequest(t, manager)
	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}
	_, err = manager.CreateAllocation(fiveTuple, req.Conn, proto.ProtoUDP,
		0, time.Hour, testUser, "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)

	msg := authenticatedConnectMsg(t, staticKey, proto.PeerAddress{
		IP:   net.ParseIP("192.0.2.10"),
		Port: 9,
	})
	_ = handleConnectRequest(req, msg)

	select {
	case <-dialed:
	default:
		t.Fatal("same-family Connect request must still reach the dialer")
	}
}

// TestSecurityChannelDataCrossFamilyDropped proves ChannelData cannot relay
// to a peer of a different family, even with a stale channel binding present.
func TestSecurityChannelDataCrossFamilyDropped(t *testing.T) {
	manager := newSecurityTestManager(t)
	req, _ := newSecurityRequest(t, manager)

	fiveTuple := &allocation.FiveTuple{
		SrcAddr:  req.SrcAddr,
		DstAddr:  req.Conn.LocalAddr(),
		Protocol: allocation.UDP,
	}
	alloc, err := manager.CreateAllocation(fiveTuple, req.Conn, proto.ProtoUDP,
		0, time.Hour, testUser, "", proto.RequestedFamilyIPv4)
	assert.NoError(t, err)

	crossFamilyPeer := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080}
	assert.NoError(t, alloc.AddChannelBind(
		allocation.NewChannelBind(0x4000, crossFamilyPeer, req.Log),
		10*time.Minute, 5*time.Minute))

	err = handleChannelData(req, &proto.ChannelData{Number: 0x4000, Data: []byte("pwn")})
	assert.ErrorIs(t, err, errPeerAddressFamilyMismatch)
}

func assertLastErrorCode(t *testing.T, conn net.PacketConn, method stun.Method, code stun.ErrorCode) {
	t.Helper()
	var raw []byte
	switch c := conn.(type) {
	case *capturePacketConn:
		raw = c.LastWrite()
	case *unclassifiablePacketConn:
		raw = c.capturePacketConn.LastWrite()
	default:
		assert.Fail(t, "unexpected conn type %T", conn)

		return
	}
	if !assert.NotEmpty(t, raw) {
		return
	}
	res := &stun.Message{Raw: append([]byte(nil), raw...)}
	assert.NoError(t, res.Decode())
	assert.Equal(t, method, res.Type.Method)
	var errorCode stun.ErrorCodeAttribute
	assert.NoError(t, errorCode.GetFrom(res))
	assert.Equal(t, code, errorCode.Code)
}

// unclassifiablePacketConn reports a local address that cannot be reduced to
// an IP address, so the server has no basis for picking an address family.
type unclassifiablePacketConn struct {
	*capturePacketConn
}

func (c *unclassifiablePacketConn) LocalAddr() net.Addr {
	return unclassifiableAddr{}
}

type unclassifiableAddr struct{}

func (unclassifiableAddr) Network() string { return "udp" }
func (unclassifiableAddr) String() string  { return "unclassifiable" }

// TestSecurityAllocateUnknownFamilyFails proves that when no
// REQUESTED-ADDRESS-FAMILY is supplied and the listener/client addresses do
// not yield a classifiable family, the allocation fails with 440 instead of
// silently defaulting to IPv4 and opening an unintended relay scope.
func TestSecurityAllocateUnknownFamilyFails(t *testing.T) {
	manager := newSecurityTestManager(t)
	nonceHash, err := NewShortNonceHash(0)
	assert.NoError(t, err)
	staticKey, err := nonceHash.Generate()
	assert.NoError(t, err)

	conn := &unclassifiablePacketConn{
		capturePacketConn: newCapturePacketConn(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478}),
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	req := Request{
		AllocationManager:   manager,
		NonceHash:           nonceHash,
		Conn:                conn,
		SrcAddr:             unclassifiableAddr{},
		Log:                 &captureLogger{},
		AllocationLifetime:  time.Hour,
		StrictAddressFamily: false,
		AuthHandler: func(*auth.RequestAttributes) (string, []byte, bool) {
			return testUser, []byte(staticKey), true
		},
	}

	msg := &stun.Message{}
	msg.TransactionID = stun.NewTransactionID()
	assert.NoError(t, msg.Build(stun.NewType(stun.MethodAllocate, stun.ClassRequest)))
	assert.NoError(t, (proto.RequestedTransport{Protocol: proto.ProtoUDP}).AddTo(msg))
	assert.NoError(t, (stun.Nonce(staticKey)).AddTo(msg))
	assert.NoError(t, (stun.Realm("pion.ly")).AddTo(msg))
	assert.NoError(t, (stun.Username(testUser)).AddTo(msg))
	assert.NoError(t, (stun.MessageIntegrity(staticKey)).AddTo(msg))

	err = handleAllocateRequest(req, msg)
	assert.Error(t, err)
	assertLastErrorCode(t, conn, stun.MethodAllocate, stun.CodeAddrFamilyNotSupported)
	assert.Zero(t, manager.AllocationCount(), "no allocation may be created for an unknown family")
}

// TestSecurityAllocateExplicitFamilyStillAccepted ensures an explicit, valid
// REQUESTED-ADDRESS-FAMILY keeps working even when the listener address cannot
// be classified: the client's explicit choice must not be overridden.
func TestSecurityAllocateExplicitFamilyStillAccepted(t *testing.T) {
	logger := &captureLogger{}
	manager, err := allocation.NewManager(allocation.ManagerConfig{
		AllocatePacketConn: func(conf allocation.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
			con, listenErr := net.ListenPacket(conf.Network, "127.0.0.1:0") // nolint: noctx
			if listenErr != nil {
				return nil, nil, listenErr
			}

			return con, con.LocalAddr(), nil
		},
		AllocateListener: func(allocation.AllocateListenerConfig) (net.Listener, net.Addr, error) {
			return nil, nil, nil //nolint:nilnil
		},
		AllocateConn: func(allocation.AllocateConnConfig) (net.Conn, error) {
			return nil, nil //nolint:nilnil
		},
		LeveledLogger: logger,
	})
	assert.NoError(t, err)
	defer manager.Close() //nolint:errcheck

	nonceHash, err := NewShortNonceHash(0)
	assert.NoError(t, err)
	staticKey, err := nonceHash.Generate()
	assert.NoError(t, err)

	conn := &unclassifiablePacketConn{
		capturePacketConn: newCapturePacketConn(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478}),
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	req := Request{
		AllocationManager:  manager,
		NonceHash:          nonceHash,
		Conn:               conn,
		SrcAddr:            &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000},
		Log:                logger,
		AllocationLifetime: time.Hour,
		AuthHandler: func(*auth.RequestAttributes) (string, []byte, bool) {
			return testUser, []byte(staticKey), true
		},
	}

	msg := &stun.Message{}
	msg.TransactionID = stun.NewTransactionID()
	assert.NoError(t, msg.Build(stun.NewType(stun.MethodAllocate, stun.ClassRequest)))
	assert.NoError(t, (proto.RequestedTransport{Protocol: proto.ProtoUDP}).AddTo(msg))
	assert.NoError(t, proto.RequestedFamilyIPv4.AddTo(msg))
	assert.NoError(t, (stun.Nonce(staticKey)).AddTo(msg))
	assert.NoError(t, (stun.Realm("pion.ly")).AddTo(msg))
	assert.NoError(t, (stun.Username(testUser)).AddTo(msg))
	assert.NoError(t, (stun.MessageIntegrity(staticKey)).AddTo(msg))

	assert.NoError(t, handleAllocateRequest(req, msg))
	assert.Equal(t, 1, manager.AllocationCount())
}
