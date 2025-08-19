package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"radius-go/internal/store"
)

func TestAPIRequiresAPIKeyAndUserLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	rootKey := createTestAPIKey(t, st, "root")
	router := NewRouter(st, zap.NewNop())

	resp := performJSON(router, http.MethodGet, "/api/health", "", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized health check without an API key, got %d", resp.Code)
	}

	resp = performJSON(router, http.MethodPost, "/api/users", rootKey, map[string]string{
		"username": "alice",
		"password": "correct-password",
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected user creation status %d, got %d: %s", http.StatusCreated, resp.Code, resp.Body.String())
	}
	accepted, reason, err := st.AuthenticateUser(ctx, "alice", "correct-password")
	if err != nil {
		t.Fatalf("authenticate user: %v", err)
	}
	if !accepted || reason != "ok" {
		t.Fatalf("expected created user to authenticate, accepted=%v reason=%s", accepted, reason)
	}

	resp = performJSON(router, http.MethodPost, "/api/users", rootKey, map[string]string{
		"username": "alice",
		"password": "correct-password",
	})
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected duplicate user conflict, got %d", resp.Code)
	}

	resp = performJSON(router, http.MethodPatch, "/api/users/alice/password", rootKey, map[string]string{
		"password": "updated-password",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("expected password update status %d, got %d: %s", http.StatusOK, resp.Code, resp.Body.String())
	}
	accepted, _, err = st.AuthenticateUser(ctx, "alice", "correct-password")
	if err != nil {
		t.Fatalf("authenticate old password: %v", err)
	}
	if accepted {
		t.Fatalf("expected old password to be rejected")
	}
	accepted, reason, err = st.AuthenticateUser(ctx, "alice", "updated-password")
	if err != nil {
		t.Fatalf("authenticate updated password: %v", err)
	}
	if !accepted || reason != "ok" {
		t.Fatalf("expected updated password to authenticate, accepted=%v reason=%s", accepted, reason)
	}

	resp = performJSON(router, http.MethodPost, "/api/users/alice/suspend", rootKey, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected user suspension status %d, got %d", http.StatusOK, resp.Code)
	}
	accepted, reason, err = st.AuthenticateUser(ctx, "alice", "updated-password")
	if err != nil {
		t.Fatalf("authenticate suspended user: %v", err)
	}
	if accepted || reason != "user_disabled" {
		t.Fatalf("expected suspended user to be rejected, accepted=%v reason=%s", accepted, reason)
	}

	resp = performJSON(router, http.MethodDelete, "/api/users/alice", rootKey, nil)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected user deletion status %d, got %d", http.StatusNoContent, resp.Code)
	}
	accepted, reason, err = st.AuthenticateUser(ctx, "alice", "updated-password")
	if err != nil {
		t.Fatalf("authenticate deleted user: %v", err)
	}
	if accepted || reason != "user_not_found" {
		t.Fatalf("expected deleted user to be rejected, accepted=%v reason=%s", accepted, reason)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	st := newTestStore(t)
	rootKey := createTestAPIKey(t, st, "root")
	router := NewRouter(st, zap.NewNop())

	resp := performJSON(router, http.MethodPost, "/api/api-keys", rootKey, map[string]string{"name": "operator"})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected API key creation status %d, got %d: %s", http.StatusCreated, resp.Code, resp.Body.String())
	}
	var created struct {
		APIKey struct {
			ID int64 `json:"id"`
		} `json:"api_key"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created API key: %v", err)
	}
	if created.APIKey.ID == 0 || created.Key == "" {
		t.Fatalf("expected created API key id and one-time key value")
	}

	resp = performJSON(router, http.MethodGet, "/api/health", created.Key, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected new API key to authenticate, got %d", resp.Code)
	}

	resp = performJSON(router, http.MethodPost, "/api/api-keys/"+itoa(created.APIKey.ID)+"/suspend", rootKey, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected API key suspension status %d, got %d", http.StatusOK, resp.Code)
	}

	resp = performJSON(router, http.MethodGet, "/api/health", created.Key, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected suspended API key to be unauthorized, got %d", resp.Code)
	}

	resp = performJSON(router, http.MethodDelete, "/api/api-keys/"+itoa(created.APIKey.ID), rootKey, nil)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected API key deletion status %d, got %d", http.StatusNoContent, resp.Code)
	}

	resp = performJSON(router, http.MethodPost, "/api/api-keys/1/suspend", rootKey, nil)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected last active API key protection conflict, got %d", resp.Code)
	}
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, _, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "radius-go-test.db"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close test store: %v", err)
		}
	})
	return st
}

func createTestAPIKey(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	created, err := st.CreateAPIKey(context.Background(), name)
	if err != nil {
		t.Fatalf("create test API key: %v", err)
	}
	return created.Key
}

func performJSON(router http.Handler, method, path, apiKey string, body any) *httptest.ResponseRecorder {
	var requestBody bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&requestBody).Encode(body)
	}
	req := httptest.NewRequest(method, path, &requestBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}
