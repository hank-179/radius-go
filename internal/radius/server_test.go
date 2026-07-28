package radius

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"radius-go/internal/config"
)

func TestRadiusAcceptAndReject(t *testing.T) {
	addr, cleanup := startTestRadiusServer(t, []config.ClientConfig{
		{Name: "local", Network: "127.0.0.1/32", Secret: "shared-secret"},
	}, fakeAuthenticator{users: map[string]string{"alice": "correct-password"}})
	defer cleanup()

	code, err := sendAccessRequest(t, addr, "shared-secret", "alice", "correct-password")
	if err != nil {
		t.Fatalf("send accepted request: %v", err)
	}
	if code != codeAccessAccept {
		t.Fatalf("expected Access-Accept, got code %d", code)
	}

	code, err = sendAccessRequest(t, addr, "shared-secret", "alice", "wrong-password")
	if err != nil {
		t.Fatalf("send rejected request: %v", err)
	}
	if code != codeAccessReject {
		t.Fatalf("expected Access-Reject, got code %d", code)
	}
}

func TestRadiusDropsUnknownClients(t *testing.T) {
	addr, cleanup := startTestRadiusServer(t, []config.ClientConfig{
		{Name: "not-local", Network: "192.0.2.0/24", Secret: "shared-secret"},
	}, fakeAuthenticator{users: map[string]string{"alice": "correct-password"}})
	defer cleanup()

	_, err := sendAccessRequest(t, addr, "shared-secret", "alice", "correct-password")
	if err == nil {
		t.Fatalf("expected request from an unauthorized client network to time out")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout for dropped packet, got %v", err)
	}
}

func TestRadiusLimitsConcurrentRequests(t *testing.T) {
	auth := &blockingAuthenticator{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	addr, cleanup := startTestRadiusServerWithLimit(t, []config.ClientConfig{
		{Name: "local", Network: "127.0.0.1/32", Secret: "shared-secret"},
	}, auth, 1)
	defer cleanup()

	type result struct {
		code byte
		err  error
	}
	firstResult := make(chan result, 1)
	go func() {
		code, err := sendAccessRequestWithTimeout(addr, "shared-secret", "alice", "correct-password", time.Second)
		firstResult <- result{code: code, err: err}
	}()

	select {
	case <-auth.started:
	case <-time.After(time.Second):
		t.Fatal("first RADIUS request did not reach the authenticator")
	}

	_, err := sendAccessRequestWithTimeout(addr, "shared-secret", "bob", "correct-password", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected a request above the concurrency limit to be dropped")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected the dropped request to time out, got %v", err)
	}
	if calls := auth.calls.Load(); calls != 1 {
		t.Fatalf("expected only one concurrent authentication call, got %d", calls)
	}

	close(auth.release)
	select {
	case result := <-firstResult:
		if result.err != nil {
			t.Fatalf("first RADIUS request failed: %v", result.err)
		}
		if result.code != codeAccessAccept {
			t.Fatalf("expected first RADIUS request to be accepted, got code %d", result.code)
		}
	case <-time.After(time.Second):
		t.Fatal("first RADIUS request did not complete after releasing the authenticator")
	}
}

func TestRadiusWaitsForInFlightRequestsOnShutdown(t *testing.T) {
	auth := &blockingAuthenticator{
		started:       make(chan struct{}, 1),
		release:       make(chan struct{}),
		ignoreContext: true,
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	srv, err := NewServer("127.0.0.1:0", 1, []config.ClientConfig{
		{Name: "local", Network: "127.0.0.1/32", Secret: "shared-secret"},
	}, auth, zap.NewNop())
	if err != nil {
		t.Fatalf("create RADIUS server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	released := false
	defer func() {
		cancel()
		if !released {
			close(auth.release)
		}
		_ = conn.Close()
	}()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, conn)
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("open client UDP socket: %v", err)
	}
	defer clientConn.Close()
	request, err := buildAccessRequest(7, []byte("shared-secret"), "alice", "correct-password")
	if err != nil {
		t.Fatalf("build access request: %v", err)
	}
	if _, err := clientConn.WriteToUDP(request, conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write access request: %v", err)
	}

	select {
	case <-auth.started:
	case <-time.After(time.Second):
		t.Fatal("RADIUS request did not reach the authenticator")
	}

	cancel()
	select {
	case err := <-errCh:
		t.Fatalf("server returned before the in-flight request completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(auth.release)
	released = true
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RADIUS server stopped with error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RADIUS server did not stop after the in-flight request completed")
	}
}

type fakeAuthenticator struct {
	users    map[string]string
	disabled map[string]bool
	err      error
}

func (f fakeAuthenticator) AuthenticateUser(_ context.Context, username, password string) (bool, string, error) {
	if f.err != nil {
		return false, "lookup_failed", f.err
	}
	expected, ok := f.users[username]
	if !ok {
		return false, "user_not_found", nil
	}
	if f.disabled[username] {
		return false, "user_disabled", nil
	}
	if password != expected {
		return false, "invalid_password", nil
	}
	return true, "ok", nil
}

type blockingAuthenticator struct {
	started       chan struct{}
	release       chan struct{}
	ignoreContext bool
	calls         atomic.Int32
}

func (a *blockingAuthenticator) AuthenticateUser(ctx context.Context, _, _ string) (bool, string, error) {
	a.calls.Add(1)
	select {
	case a.started <- struct{}{}:
	default:
	}
	if a.ignoreContext {
		<-a.release
		return true, "ok", nil
	}
	select {
	case <-a.release:
		return true, "ok", nil
	case <-ctx.Done():
		return false, "lookup_failed", ctx.Err()
	}
}

func startTestRadiusServer(t *testing.T, clients []config.ClientConfig, auth Authenticator) (*net.UDPAddr, func()) {
	t.Helper()
	return startTestRadiusServerWithLimit(t, clients, auth, 64)
}

func startTestRadiusServerWithLimit(t *testing.T, clients []config.ClientConfig, auth Authenticator, maxConcurrentRequests int) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	srv, err := NewServer("127.0.0.1:0", maxConcurrentRequests, clients, auth, zap.NewNop())
	if err != nil {
		t.Fatalf("create radius server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, conn)
	}()

	cleanup := func() {
		cancel()
		_ = conn.Close()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("radius server stopped with error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("radius server did not stop")
		}
	}
	return conn.LocalAddr().(*net.UDPAddr), cleanup
}

func sendAccessRequest(t *testing.T, serverAddr *net.UDPAddr, secret, username, password string) (byte, error) {
	t.Helper()
	return sendAccessRequestWithTimeout(serverAddr, secret, username, password, 500*time.Millisecond)
}

func sendAccessRequestWithTimeout(serverAddr *net.UDPAddr, secret, username, password string, timeout time.Duration) (byte, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return 0, fmt.Errorf("open client UDP socket: %w", err)
	}
	defer conn.Close()

	request, err := buildAccessRequest(7, []byte(secret), username, password)
	if err != nil {
		return 0, fmt.Errorf("build access request: %w", err)
	}
	if _, err := conn.WriteToUDP(request, serverAddr); err != nil {
		return 0, fmt.Errorf("write access request: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("set read deadline: %w", err)
	}
	buf := make([]byte, maxPacketLength)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	if n < headerLength {
		return 0, fmt.Errorf("response too short: %d", n)
	}
	return buf[0], nil
}

func buildAccessRequest(identifier byte, secret []byte, username, password string) ([]byte, error) {
	authenticator, err := randomAuthenticator()
	if err != nil {
		return nil, err
	}
	encryptedPassword, err := encryptUserPassword([]byte(password), secret, authenticator)
	if err != nil {
		return nil, err
	}
	attrs, err := encodeAttributes([]attribute{
		{Type: attrUserName, Value: []byte(username)},
		{Type: attrUserPassword, Value: encryptedPassword},
	})
	if err != nil {
		return nil, err
	}
	length := headerLength + len(attrs)
	packet := make([]byte, length)
	packet[0] = codeAccessRequest
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[4:20], authenticator[:])
	copy(packet[20:], attrs)
	return packet, nil
}
