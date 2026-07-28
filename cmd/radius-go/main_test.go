package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRunServersShutsDownAPIWhenRadiusFails(t *testing.T) {
	radiusErr := errors.New("RADIUS listener failed")
	api := newFakeAPIServer(nil)
	radius := newFakeRadiusServer(radiusErr)

	err := runServers(context.Background(), api, radius, zap.NewNop())
	if !errors.Is(err, radiusErr) {
		t.Fatalf("expected RADIUS error, got %v", err)
	}
	if calls := api.shutdownCalls.Load(); calls != 1 {
		t.Fatalf("expected one API shutdown call, got %d", calls)
	}
	assertClosed(t, api.returned, "API server did not return")
}

func TestRunServersCancelsRadiusWhenAPIFails(t *testing.T) {
	apiErr := errors.New("API listener failed")
	api := newFakeAPIServer(apiErr)
	radius := newFakeRadiusServer(nil)

	err := runServers(context.Background(), api, radius, zap.NewNop())
	if !errors.Is(err, apiErr) {
		t.Fatalf("expected API error, got %v", err)
	}
	assertClosed(t, radius.returned, "RADIUS server did not return")
}

func TestRunServersGracefullyStopsOnContextCancellation(t *testing.T) {
	api := newFakeAPIServer(nil)
	radius := newFakeRadiusServer(nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServers(ctx, api, radius, zap.NewNop())
	}()

	assertClosed(t, api.started, "API server did not start")
	assertClosed(t, radius.started, "RADIUS server did not start")
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected a clean shutdown, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("servers did not stop after context cancellation")
	}
	if calls := api.shutdownCalls.Load(); calls != 1 {
		t.Fatalf("expected one API shutdown call, got %d", calls)
	}
	assertClosed(t, api.returned, "API server did not return")
	assertClosed(t, radius.returned, "RADIUS server did not return")
}

type fakeAPIServer struct {
	listenErr     error
	started       chan struct{}
	stop          chan struct{}
	returned      chan struct{}
	stopOnce      sync.Once
	shutdownCalls atomic.Int32
}

func newFakeAPIServer(listenErr error) *fakeAPIServer {
	return &fakeAPIServer{
		listenErr: listenErr,
		started:   make(chan struct{}),
		stop:      make(chan struct{}),
		returned:  make(chan struct{}),
	}
}

func (s *fakeAPIServer) ListenAndServe() error {
	close(s.started)
	defer close(s.returned)
	if s.listenErr != nil {
		return s.listenErr
	}
	<-s.stop
	return http.ErrServerClosed
}

func (s *fakeAPIServer) Shutdown(context.Context) error {
	s.shutdownCalls.Add(1)
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

func (s *fakeAPIServer) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

type fakeRadiusServer struct {
	listenErr error
	started   chan struct{}
	returned  chan struct{}
}

func newFakeRadiusServer(listenErr error) *fakeRadiusServer {
	return &fakeRadiusServer{
		listenErr: listenErr,
		started:   make(chan struct{}),
		returned:  make(chan struct{}),
	}
}

func (s *fakeRadiusServer) ListenAndServe(ctx context.Context) error {
	close(s.started)
	defer close(s.returned)
	if s.listenErr != nil {
		return s.listenErr
	}
	<-ctx.Done()
	return nil
}

func assertClosed(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}
