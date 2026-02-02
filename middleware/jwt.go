package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gralka/authkit/token"
)

type contextKey struct{}

var claimsKey = contextKey{}

var (
	errMissingAuthorization = errors.New("middleware: missing authorization header")
	errInvalidAuthorization = errors.New("middleware: invalid authorization format")
	errInvalidToken         = errors.New("middleware: invalid token")
)

// ErrorHandler handles authorization errors.
// It can customize the response while still relying on RequireJWT defaults.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options configures RequireJWT behavior.
type Options struct {
	// HeaderName is the name of the header containing the token.
	// Defaults to "Authorization".
	HeaderName string

	// Scheme is the auth scheme prefix (e.g. "Bearer").
	// Defaults to "Bearer" and is compared case-insensitively.
	Scheme string

	// ErrorHandler is called on authorization errors.
	// Defaults to a 401 with a plain-text error message.
	ErrorHandler ErrorHandler
}

func applyDefaults(opts Options) Options {
	if opts.HeaderName == "" {
		opts.HeaderName = "Authorization"
	}
	if opts.Scheme == "" {
		opts.Scheme = "Bearer"
	}
	if opts.ErrorHandler == nil {
		opts.ErrorHandler = defaultErrorHandler
	}
	return opts
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errMissingAuthorization):
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
	case errors.Is(err, errInvalidAuthorization):
		http.Error(w, "invalid authorization format", http.StatusUnauthorized)
	default:
		http.Error(w, "invalid token", http.StatusUnauthorized)
	}
}

// RequireJWT validates the JWT from the Authorization: Bearer <token> header.
// On success, it stores the parsed claims in the request context and calls next.
// On failure, it returns 401 Unauthorized.
func RequireJWT(cfg token.Config) func(http.Handler) http.Handler {
	return RequireJWTWithOptions(cfg, Options{})
}

// RequireJWTWithOptions validates the JWT from the configured header.
// On success, it stores the parsed claims in the request context and calls next.
// On failure, it calls the configured ErrorHandler (default: 401 Unauthorized).
func RequireJWTWithOptions(cfg token.Config, opts Options) func(http.Handler) http.Handler {
	opts = applyDefaults(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(opts.HeaderName)
			if authHeader == "" {
				opts.ErrorHandler(w, r, errMissingAuthorization)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], opts.Scheme) {
				opts.ErrorHandler(w, r, errInvalidAuthorization)
				return
			}

			rawToken := strings.TrimSpace(parts[1])
			if rawToken == "" {
				opts.ErrorHandler(w, r, errInvalidToken)
				return
			}
			if len(strings.Fields(parts[1])) != 1 {
				opts.ErrorHandler(w, r, errInvalidAuthorization)
				return
			}

			claims, err := token.ValidateToken(cfg, rawToken)
			if err != nil {
				opts.ErrorHandler(w, r, errInvalidToken)
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
	return ClaimsFromContext(r.Context())
}

// ClaimsFromContext retrieves the validated claims from a context.
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*token.Claims)
	return claims, ok
}
