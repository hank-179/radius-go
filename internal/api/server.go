package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"radius-go/internal/store"
)

const apiKeyContextKey = "api_key_id"
const clientIPContextKey = "client_ip"
const defaultPageSize = 20
const maxPageSize = 100

type RouterConfig struct {
	AllowedSources []string
	TrustedProxies []string
}

type userResponse struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type apiKeyResponse struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Disabled   bool    `json:"disabled"`
	LastUsedAt *string `json:"last_used_at"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}

type paginationResponse struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

func NewRouter(st *store.Store, logger *zap.Logger, cfg RouterConfig) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)

	sourceAllowlist, err := newIPAllowlist(cfg.AllowedSources)
	if err != nil {
		return nil, fmt.Errorf("allowed API sources: %w", err)
	}
	trustedProxies, err := newIPAllowlist(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trusted API proxies: %w", err)
	}
	ipResolver := clientIPResolver{trustedProxies: trustedProxies}

	router := gin.New()
	router.HandleMethodNotAllowed = true
	router.Use(recovery(logger), realIPMiddleware(ipResolver), requestLogger(logger), sourceAllowlistMiddleware(sourceAllowlist, logger), apiKeyMiddleware(st, logger))

	api := router.Group("/api")
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	api.GET("/users", listUsers(st))
	api.POST("/users", createUser(st))
	api.PATCH("/users/:username/password", updateUserPassword(st))
	api.POST("/users/:username/suspend", suspendUser(st))
	api.DELETE("/users/:username", deleteUser(st))

	api.GET("/api-keys", listAPIKeys(st))
	api.POST("/api-keys", createAPIKey(st))
	api.POST("/api-keys/:id/suspend", suspendAPIKey(st))
	api.DELETE("/api-keys/:id", deleteAPIKey(st))

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	})
	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method_not_allowed"})
	})
	return router, nil
}

type ipAllowlist struct {
	networks []*net.IPNet
}

func newIPAllowlist(entries []string) (*ipAllowlist, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	allowlist := &ipAllowlist{networks: make([]*net.IPNet, 0, len(entries))}
	for i, entry := range entries {
		network, err := parseSourceEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("parse entry %d: %w", i, err)
		}
		allowlist.networks = append(allowlist.networks, network)
	}
	return allowlist, nil
}

func parseSourceEntry(entry string) (*net.IPNet, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, errors.New("source is empty")
	}
	if ip := net.ParseIP(entry); ip != nil {
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, network, err := net.ParseCIDR(entry)
	if err != nil {
		return nil, err
	}
	if ipv4 := network.IP.To4(); ipv4 != nil {
		network.IP = ipv4
	}
	return network, nil
}

type clientIPResolver struct {
	trustedProxies *ipAllowlist
}

func realIPMiddleware(resolver clientIPResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ip, ok := resolver.resolve(c.Request); ok {
			c.Set(clientIPContextKey, ip)
		}
		c.Next()
	}
}

func (r clientIPResolver) resolve(req *http.Request) (net.IP, bool) {
	peerIP, ok := remoteIP(req.RemoteAddr)
	if !ok {
		return nil, false
	}
	if r.trustedProxies == nil || !r.trustedProxies.allows(peerIP) {
		return peerIP, true
	}
	if ip, ok := clientIPFromForwardedFor(req.Header.Get("X-Forwarded-For"), r.trustedProxies); ok {
		return ip, true
	}
	if ip, ok := headerIP(req.Header.Get("X-Real-IP")); ok {
		return ip, true
	}
	return peerIP, true
}

func clientIPFromForwardedFor(value string, trustedProxies *ipAllowlist) (net.IP, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, false
	}
	parts := strings.Split(value, ",")
	ips := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		ip, ok := headerIP(part)
		if !ok {
			return nil, false
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, false
	}
	for i := len(ips) - 1; i >= 0; i-- {
		if trustedProxies == nil || !trustedProxies.allows(ips[i]) {
			return ips[i], true
		}
	}
	return ips[0], true
}

func headerIP(value string) (net.IP, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return nil, false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4, true
	}
	return ip, true
}

func sourceAllowlistMiddleware(allowlist *ipAllowlist, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowlist == nil || !isAPIPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		ip, ok := requestClientIP(c)
		if !ok || !allowlist.allows(ip) {
			logger.Warn("Rejected API request from unauthorized source", zap.String("client_ip", clientIPString(c)), zap.String("remote_addr", c.Request.RemoteAddr), zap.String("path", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "source_forbidden"})
			return
		}
		c.Next()
	}
}

func remoteIP(remoteAddr string) (net.IP, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4, true
	}
	return ip, true
}

func (a *ipAllowlist) allows(ip net.IP) bool {
	for _, network := range a.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestClientIP(c *gin.Context) (net.IP, bool) {
	value, exists := c.Get(clientIPContextKey)
	if !exists {
		return remoteIP(c.Request.RemoteAddr)
	}
	ip, ok := value.(net.IP)
	return ip, ok && ip != nil
}

func clientIPString(c *gin.Context) string {
	ip, ok := requestClientIP(c)
	if !ok {
		return ""
	}
	return ip.String()
}

func apiKeyMiddleware(st *store.Store, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAPIPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		apiKey, err := st.AuthenticateAPIKey(c.Request.Context(), c.GetHeader("X-API-Key"))
		if err != nil {
			if !errors.Is(err, store.ErrUnauthorized) {
				logger.Error("API key authentication failed", zap.Error(err))
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set(apiKeyContextKey, apiKey.ID)
		c.Next()
	}
}

func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

func createUser(st *store.Store) gin.HandlerFunc {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		username, err := validateUsername(req.Username)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validatePassword(req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user, err := st.CreateUser(c.Request.Context(), username, req.Password)
		if err != nil {
			writeStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"user": toUserResponse(user)})
	}
}

func listUsers(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, ok := parsePagination(c)
		if !ok {
			return
		}
		username, err := validateUsernameSearch(c.Query("username"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result, err := st.ListUsers(c.Request.Context(), store.UserListFilter{Username: username}, page)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"users":      toUserResponses(result.Users),
			"pagination": toPaginationResponse(page, result.Total),
		})
	}
}

func updateUserPassword(st *store.Store) gin.HandlerFunc {
	type request struct {
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		username, err := validateUsername(c.Param("username"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		if err := validatePassword(req.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user, err := st.UpdateUserPassword(c.Request.Context(), username, req.Password)
		if err != nil {
			writeStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
	}
}

func suspendUser(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := validateUsername(c.Param("username"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user, err := st.SuspendUser(c.Request.Context(), username)
		if err != nil {
			writeStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
	}
}

func deleteUser(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := validateUsername(c.Param("username"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := st.DeleteUser(c.Request.Context(), username); err != nil {
			writeStoreError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func createAPIKey(st *store.Store) gin.HandlerFunc {
	type request struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		var req request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		name, err := validateName(req.Name)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		created, err := st.CreateAPIKey(c.Request.Context(), name)
		if err != nil {
			writeStoreError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"api_key": toAPIKeyResponse(&created.APIKey),
			"key":     created.Key,
		})
	}
}

func listAPIKeys(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, ok := parsePagination(c)
		if !ok {
			return
		}
		result, err := st.ListAPIKeys(c.Request.Context(), page)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"api_keys":   toAPIKeyResponses(result.APIKeys),
			"pagination": toPaginationResponse(page, result.Total),
		})
	}
}

func suspendAPIKey(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := parseID(c)
		if !ok {
			return
		}
		apiKey, err := st.SuspendAPIKey(c.Request.Context(), id)
		if err != nil {
			writeStoreError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"api_key": toAPIKeyResponse(apiKey)})
	}
}

func deleteAPIKey(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := parseID(c)
		if !ok {
			return
		}
		if err := st.DeleteAPIKey(c.Request.Context(), id); err != nil {
			writeStoreError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("API request completed",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", clientIPString(c)),
			zap.String("remote_addr", c.Request.RemoteAddr),
		)
	}
}

func recovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("Recovered from API panic", zap.Any("panic", recovered), zap.Stack("stack"))
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
		}()
		c.Next()
	}
}

func parseID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_id"})
		return 0, false
	}
	return id, true
}

func parsePagination(c *gin.Context) (store.Page, bool) {
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return store.Page{}, false
	}
	pageSize, ok := parsePositiveIntQuery(c, "page_size", defaultPageSize)
	if !ok {
		return store.Page{}, false
	}
	if pageSize > maxPageSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page_size_too_large"})
		return store.Page{}, false
	}
	return store.Page{Page: page, PageSize: pageSize}, true
}

func parsePositiveIntQuery(c *gin.Context, name string, fallback int) (int, bool) {
	value := strings.TrimSpace(c.Query(name))
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_" + name})
		return 0, false
	}
	return parsed, true
}

func writeStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, store.ErrAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{"error": "already_exists"})
	case errors.Is(err, store.ErrLastAPIKey):
		c.JSON(http.StatusConflict, gin.H{"error": "last_active_api_key"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
	}
}

func toUserResponse(user *store.User) userResponse {
	return userResponse{
		ID:        user.ID,
		Username:  user.Username,
		Disabled:  user.Disabled,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func toUserResponses(users []store.User) []userResponse {
	out := make([]userResponse, 0, len(users))
	for i := range users {
		out = append(out, toUserResponse(&users[i]))
	}
	return out
}

func toAPIKeyResponse(apiKey *store.APIKey) apiKeyResponse {
	var lastUsedAt *string
	if apiKey.LastUsedAt.Valid {
		lastUsedAt = &apiKey.LastUsedAt.String
	}
	return apiKeyResponse{
		ID:         apiKey.ID,
		Name:       apiKey.Name,
		Disabled:   apiKey.Disabled,
		LastUsedAt: lastUsedAt,
		CreatedAt:  apiKey.CreatedAt,
		UpdatedAt:  apiKey.UpdatedAt,
	}
}

func toAPIKeyResponses(apiKeys []store.APIKey) []apiKeyResponse {
	out := make([]apiKeyResponse, 0, len(apiKeys))
	for i := range apiKeys {
		out = append(out, toAPIKeyResponse(&apiKeys[i]))
	}
	return out
}

func toPaginationResponse(page store.Page, total int) paginationResponse {
	totalPages := 0
	if total > 0 {
		totalPages = (total + page.PageSize - 1) / page.PageSize
	}
	return paginationResponse{
		Page:       page.Page,
		PageSize:   page.PageSize,
		Total:      total,
		TotalPages: totalPages,
	}
}

func validateUsername(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("username_required")
	}
	if len(value) > 128 {
		return "", errors.New("username_too_long")
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' {
			return "", errors.New("username_invalid")
		}
	}
	return value, nil
}

func validateUsernameSearch(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return "", errors.New("username_search_too_long")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("username_search_invalid")
		}
	}
	return value, nil
}

func validatePassword(value string) error {
	if len(value) < 8 {
		return errors.New("password_too_short")
	}
	if len(value) > 72 {
		return errors.New("password_too_long")
	}
	if strings.ContainsRune(value, 0) {
		return errors.New("password_invalid")
	}
	return nil
}

func validateName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("name_required")
	}
	if len(value) > 128 {
		return "", errors.New("name_too_long")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("name_invalid")
		}
	}
	return value, nil
}
