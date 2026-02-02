package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gralka/authkit/middleware"
	"github.com/gralka/authkit/token"
)

func TestRequireJWT_MissingAuthorizationHeader(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	body := rec.Body.String()
	if body != "missing authorization header\n" {
		t.Fatalf("unexpected error message: %s", body)
	}
}

func TestRequireJWT_InvalidAuthorizationFormat(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "some-token"},
		{"wrong prefix", "Basic some-token"},
		{"only bearer", "Bearer"},
		{"extra parts", "Bearer token extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", tt.header)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}

			body := rec.Body.String()
			if body != "invalid authorization format\n" {
				t.Fatalf("unexpected error message: %s", body)
			}
		})
	}
}

func TestRequireJWT_InvalidToken(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
	}{
		{"malformed token", "not.a.valid.jwt"},
		{"empty token", ""},
		{"random string", "randomstring"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}

			body := rec.Body.String()
			if body != "invalid token\n" {
				t.Fatalf("unexpected error message: %s", body)
			}
		})
	}
}

func TestRequireJWT_WrongSecret(t *testing.T) {
	genCfg := token.Config{
		Secret: []byte("secret-a"),
		TTL:    time.Hour,
	}

	// Generate token with secret-a
	tokenStr, err := token.GenerateToken(genCfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Try to validate with secret-b
	validationCfg := token.Config{
		Secret: []byte("secret-b"),
		TTL:    time.Hour,
	}

	handler := middleware.RequireJWT(validationCfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireJWT_ValidToken(t *testing.T) {
	cfg := token.Config{
		Secret:   []byte("test-secret"),
		TTL:      time.Hour,
		Issuer:   "test-issuer",
		Audience: "test-audience",
	}

	claims := token.Claims{}
	tokenStr, err := token.GenerateToken(cfg, claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	nextCalled := false
	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}

	if rec.Body.String() != "success" {
		t.Fatalf("unexpected response body: %s", rec.Body.String())
	}
}

func TestRequireJWT_ClaimsInContext(t *testing.T) {
	cfg := token.Config{
		Secret:   []byte("test-secret"),
		TTL:      time.Hour,
		Issuer:   "test-issuer",
		Audience: "test-audience",
	}

	claims := token.Claims{
		Roles: []string{"admin", "user"},
	}
	tokenStr, err := token.GenerateToken(cfg, claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedClaims, ok := middleware.GetClaims(r)
		if !ok {
			t.Fatal("expected claims to be in context")
		}

		if extractedClaims == nil {
			t.Fatal("expected non-nil claims")
		}

		if extractedClaims.Issuer != cfg.Issuer {
			t.Fatalf("expected issuer %q, got %q", cfg.Issuer, extractedClaims.Issuer)
		}

		if len(extractedClaims.Audience) == 0 || extractedClaims.Audience[0] != cfg.Audience {
			t.Fatalf("expected audience %q, got %v", cfg.Audience, extractedClaims.Audience)
		}

		if len(extractedClaims.Roles) != 2 {
			t.Fatalf("expected 2 roles, got %d", len(extractedClaims.Roles))
		}

		if extractedClaims.Roles[0] != "admin" || extractedClaims.Roles[1] != "user" {
			t.Fatalf("unexpected roles: %v", extractedClaims.Roles)
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireJWTWithOptions_CustomHeaderName(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	tokenStr, err := token.GenerateToken(cfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	nextCalled := false
	handler := middleware.RequireJWTWithOptions(cfg, middleware.Options{
		HeaderName: "X-Auth",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Auth", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
}

func TestRequireJWTWithOptions_SchemeCaseInsensitive(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	tokenStr, err := token.GenerateToken(cfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	handler := middleware.RequireJWTWithOptions(cfg, middleware.Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireJWTWithOptions_CustomErrorHandler(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	customStatus := http.StatusTeapot
	handler := middleware.RequireJWTWithOptions(cfg, middleware.Options{
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "custom error", customStatus)
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != customStatus {
		t.Fatalf("expected status %d, got %d", customStatus, rec.Code)
	}
	if rec.Body.String() != "custom error\n" {
		t.Fatalf("unexpected response body: %s", rec.Body.String())
	}
}

func TestClaimsFromContext(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
	}

	tokenStr, err := token.GenerateToken(cfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			t.Fatal("expected claims in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestGetClaims_NoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	claims, ok := middleware.GetClaims(req)
	if ok {
		t.Fatal("expected ok to be false when no claims in context")
	}
	if claims != nil {
		t.Fatal("expected nil claims when not in context")
	}
}

func TestRequireJWT_ExpiredToken(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    -time.Hour, // Already expired
	}

	claims := token.Claims{}
	tokenStr, err := token.GenerateToken(cfg, claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Use same config for validation (which will check expiry)
	handler := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d for expired token, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireJWT_IssuerMismatch(t *testing.T) {
	genCfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
		Issuer: "issuer-a",
	}

	tokenStr, err := token.GenerateToken(genCfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Validate with different issuer
	validationCfg := token.Config{
		Secret: []byte("test-secret"),
		TTL:    time.Hour,
		Issuer: "issuer-b",
	}

	handler := middleware.RequireJWT(validationCfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d for issuer mismatch, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireJWT_AudienceMismatch(t *testing.T) {
	genCfg := token.Config{
		Secret:   []byte("test-secret"),
		TTL:      time.Hour,
		Audience: "audience-a",
	}

	tokenStr, err := token.GenerateToken(genCfg, token.Claims{})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Validate with different audience
	validationCfg := token.Config{
		Secret:   []byte("test-secret"),
		TTL:      time.Hour,
		Audience: "audience-b",
	}

	handler := middleware.RequireJWT(validationCfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d for audience mismatch, got %d", http.StatusUnauthorized, rec.Code)
	}
}
