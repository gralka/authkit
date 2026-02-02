package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateToken signs the provided claims with the config defaults.
func GenerateToken(cfg Config, claims Claims) (string, error) {
	if len(cfg.Secret) == 0 {
		return "", ErrSecretRequired
	}

	now := time.Now()

	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.ExpiresAt == nil && cfg.TTL > 0 {
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
	if len(cfg.Secret) == 0 {
		return nil, ErrSecretRequired
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
