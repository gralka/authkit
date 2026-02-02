package token

import "time"

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
