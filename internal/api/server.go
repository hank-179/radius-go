package api

import (
	"errors"
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

func NewRouter(st *store.Store, logger *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.HandleMethodNotAllowed = true
	router.Use(recovery(logger), requestLogger(logger), apiKeyMiddleware(st, logger))

	api := router.Group("/api")
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	api.POST("/users", createUser(st))
	api.PATCH("/users/:username/password", updateUserPassword(st))
	api.POST("/users/:username/suspend", suspendUser(st))
	api.DELETE("/users/:username", deleteUser(st))

	api.POST("/api-keys", createAPIKey(st))
	api.POST("/api-keys/:id/suspend", suspendAPIKey(st))
	api.DELETE("/api-keys/:id", deleteAPIKey(st))

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	})
	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method_not_allowed"})
	})
	return router
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
			zap.String("client_ip", c.ClientIP()),
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
