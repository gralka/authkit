package token

import "errors"

var (
  // ErrSecretRequired is returned when a secret is not provided.
	ErrSecretRequired = errors.New("token: secret is required")

  // ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("token: invalid token")

	// ErrExpiredToken is returned when a token has expired.
	ErrExpiredToken = errors.New("token: token has expired")
)