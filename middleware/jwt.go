package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gralka/authkit/token"
)

type contextKey struct{}

var claimsKey = contextKey{}

// RequireJWT validates the JWT from the Authorization: Bearer <token> header.
// On success, it stores the parsed claims in the request context and calls next.
// On failure, it returns 401 Unauthorized.
func RequireJWT(cfg token.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			rawToken := strings.TrimSpace(parts[1])
			if rawToken == "" {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			if len(strings.Fields(parts[1])) != 1 {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			claims, err := token.ValidateToken(cfg, rawToken)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Store claims in context for downstream handlers
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves the validated claims from the request context.
func GetClaims(r *http.Request) (*token.Claims, bool) {
	claims, ok := r.Context().Value(claimsKey).(*token.Claims)
	return claims, ok
}
