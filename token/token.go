package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config defines how JWTs are generated and verified.
type Config struct {
	// Secret is the HMAC signing key (HS256).
	Secret []byte

	// Issuer identifies who minted the token (iss).
	Issuer string

	// Audience identifies who the token is intended for (aud).
	Audience string

	// TTL controls token lifetime.
	TTL time.Duration
}

// Validate reports whether the config is usable.
func (cfg Config) Validate() error {
	if len(cfg.Secret) == 0 {
		return ErrSecretRequired
	}
	return nil
}

// Claims represents authkit claims plus standard JWT registered claims.
type Claims struct {
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// SetSubject sets the registered "sub" claim without exposing jwt.RegisteredClaims.
func (c *Claims) SetSubject(subject string) {
	c.Subject = subject
}

var (
	// ErrSecretRequired is returned when a secret is not provided.
	ErrSecretRequired = errors.New("token: secret is required")

	// ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("token: invalid token")
)

// GenerateToken signs the provided claims with the config defaults.
func GenerateToken(cfg Config, claims Claims) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	now := time.Now()

	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.ExpiresAt == nil && cfg.TTL != 0 {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(cfg.TTL))
	}
	if claims.Issuer == "" && cfg.Issuer != "" {
		claims.Issuer = cfg.Issuer
	}
	if len(claims.Audience) == 0 && cfg.Audience != "" {
		claims.Audience = jwt.ClaimStrings{cfg.Audience}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(cfg.Secret)
}

// ValidateToken parses and validates a token string.
func ValidateToken(cfg Config, tokenString string) (*Claims, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	claims := &Claims{}
	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	}
	if cfg.Issuer != "" {
		options = append(options, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		options = append(options, jwt.WithAudience(cfg.Audience))
	}

	parsed, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			return cfg.Secret, nil
		},
		options...,
	)
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
