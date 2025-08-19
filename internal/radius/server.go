package radius

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"radius-go/internal/config"
)

type Authenticator interface {
	AuthenticateUser(ctx context.Context, username, password string) (bool, string, error)
}

type Client struct {
	Name    string
	Network *net.IPNet
	Secret  []byte
}

type Server struct {
	addr    string
	clients []Client
	auth    Authenticator
	logger  *zap.Logger
}

func NewServer(addr string, clientConfigs []config.ClientConfig, auth Authenticator, logger *zap.Logger) (*Server, error) {
	clients := make([]Client, 0, len(clientConfigs))
	for _, clientConfig := range clientConfigs {
		_, network, err := net.ParseCIDR(clientConfig.Network)
		if err != nil {
			return nil, fmt.Errorf("parse client network %q: %w", clientConfig.Name, err)
		}
		clients = append(clients, Client{
			Name:    clientConfig.Name,
			Network: network,
			Secret:  []byte(clientConfig.Secret),
		})
	}
	return &Server{
		addr:    addr,
		clients: clients,
		auth:    auth,
		logger:  logger,
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolve RADIUS address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen for RADIUS: %w", err)
	}
	defer conn.Close()
	return s.Serve(ctx, conn)
}

func (s *Server) Serve(ctx context.Context, conn *net.UDPConn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	buf := make([]byte, maxPacketLength)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("Failed to read RADIUS packet", zap.Error(err))
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handlePacket(ctx, conn, remoteAddr, data)
	}
}

func (s *Server) handlePacket(ctx context.Context, conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	client := s.findClient(remoteAddr.IP)
	if client == nil {
		s.logger.Warn("Dropped RADIUS packet from unauthorized client", zap.String("remote", remoteAddr.String()))
		return
	}

	pkt, err := parsePacket(data)
	if err != nil {
		s.logger.Warn("Dropped malformed RADIUS packet", zap.String("client", client.Name), zap.Error(err))
		return
	}
	if pkt.Code != codeAccessRequest {
		s.logger.Warn("Dropped unsupported RADIUS packet code", zap.String("client", client.Name), zap.Uint8("code", pkt.Code))
		return
	}

	usernameBytes, ok := pkt.firstAttribute(attrUserName)
	if !ok || len(usernameBytes) == 0 {
		s.sendResponse(conn, remoteAddr, client, pkt, codeAccessReject, "Missing User-Name")
		return
	}
	encryptedPassword, ok := pkt.firstAttribute(attrUserPassword)
	if !ok {
		s.sendResponse(conn, remoteAddr, client, pkt, codeAccessReject, "Missing User-Password")
		return
	}

	username := string(usernameBytes)
	password, err := decryptUserPassword(encryptedPassword, client.Secret, pkt.Authenticator)
	if err != nil {
		s.logger.Warn("Rejected RADIUS request with invalid User-Password", zap.String("client", client.Name), zap.String("username", username), zap.Error(err))
		s.sendResponse(conn, remoteAddr, client, pkt, codeAccessReject, "Access denied")
		return
	}

	authCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	accepted, reason, err := s.auth.AuthenticateUser(authCtx, username, password)
	if err != nil {
		s.logger.Error("RADIUS authentication failed during user lookup", zap.String("client", client.Name), zap.String("username", username), zap.Error(err))
		s.sendResponse(conn, remoteAddr, client, pkt, codeAccessReject, "Access denied")
		return
	}
	if !accepted {
		s.logger.Info("RADIUS authentication rejected", zap.String("client", client.Name), zap.String("username", username), zap.String("reason", reason))
		s.sendResponse(conn, remoteAddr, client, pkt, codeAccessReject, "Access denied")
		return
	}

	s.logger.Info("RADIUS authentication accepted", zap.String("client", client.Name), zap.String("username", username))
	s.sendResponse(conn, remoteAddr, client, pkt, codeAccessAccept, "Access granted")
}

func (s *Server) findClient(ip net.IP) *Client {
	for i := range s.clients {
		if s.clients[i].Network.Contains(ip) {
			return &s.clients[i]
		}
	}
	return nil
}

func (s *Server) sendResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, client *Client, req *packet, code byte, message string) {
	response, err := buildResponse(code, req.Identifier, req.Authenticator, client.Secret, []attribute{replyMessage(message)})
	if err != nil {
		s.logger.Error("Failed to build RADIUS response", zap.String("client", client.Name), zap.Error(err))
		return
	}
	if _, err := conn.WriteToUDP(response, remoteAddr); err != nil {
		s.logger.Error("Failed to write RADIUS response", zap.String("client", client.Name), zap.String("remote", remoteAddr.String()), zap.Error(err))
	}
}
