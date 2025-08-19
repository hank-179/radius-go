package radius

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
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

func startTestRadiusServer(t *testing.T, clients []config.ClientConfig, auth Authenticator) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	srv, err := NewServer("127.0.0.1:0", clients, auth, zap.NewNop())
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
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("open client UDP socket: %v", err)
	}
	defer conn.Close()

	request, err := buildAccessRequest(7, []byte(secret), username, password)
	if err != nil {
		t.Fatalf("build access request: %v", err)
	}
	if _, err := conn.WriteToUDP(request, serverAddr); err != nil {
		t.Fatalf("write access request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, maxPacketLength)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	if n < headerLength {
		t.Fatalf("response too short: %d", n)
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
