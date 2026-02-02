package token_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gralka/authkit/token"
)

func TestGenerateToken_SecretRequired(t *testing.T) {
	cfg := token.Config{}
	claims := token.Claims{}

	s, err := token.GenerateToken(cfg, claims)
	if err != token.ErrSecretRequired {
		t.Fatalf("expected ErrSecretRequired, got %v", err)
	}
	if s != "" {
		t.Fatalf("expected empty token when secret missing")
	}
}

func TestGenerateToken_SetsDefaultsAndSigns(t *testing.T) {
	cfg := token.Config{
		Secret:   []byte("supersecret"),
		TTL:      time.Hour,
		Issuer:   "cfg-issuer",
		Audience: "cfg-audience",
	}
	claims := token.Claims{}

	s, err := token.GenerateToken(cfg, claims)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if s == "" {
		t.Fatalf("expected token string")
	}

	parsed, err := token.ValidateToken(cfg, s)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if parsed.IssuedAt == nil {
		t.Fatalf("expected IssuedAt to be set")
	}
	if parsed.ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt to be set")
	}
	if parsed.Issuer != cfg.Issuer {
		t.Fatalf("expected issuer %q, got %q", cfg.Issuer, parsed.Issuer)
	}
	if len(parsed.Audience) == 0 || parsed.Audience[0] != cfg.Audience {
		t.Fatalf("expected audience %q, got %v", cfg.Audience, parsed.Audience)
	}
}

func TestGenerateToken_PreservesProvidedClaims(t *testing.T) {
	cfg := token.Config{
		Secret: []byte("anothersecret"),
		TTL:    time.Hour,
	}

	now := time.Now()
	exp := jwt.NewNumericDate(now.Add(2 * time.Hour))
	providedIssuer := "provided-issuer"
	providedAudience := jwt.ClaimStrings{"a", "b"}

	claims := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    providedIssuer,
			Audience:  providedAudience,
			ExpiresAt: exp,
		},
	}

	s, err := token.GenerateToken(cfg, claims)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	parsed, err := token.ValidateToken(cfg, s)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if parsed.ExpiresAt == nil || !parsed.ExpiresAt.Time.Equal(exp.Time) {
		t.Fatalf("expected ExpiresAt to be preserved")
	}
	if parsed.Issuer != providedIssuer {
		t.Fatalf("expected issuer %q, got %q", providedIssuer, parsed.Issuer)
	}
	if len(parsed.Audience) != len(providedAudience) || parsed.Audience[0] != providedAudience[0] {
		t.Fatalf("expected audience %v, got %v", providedAudience, parsed.Audience)
	}
}
func TestValidateToken_SecretRequired(t *testing.T) {
  cfg := token.Config{}
  _, err := token.ValidateToken(cfg, "token")
  if err != token.ErrSecretRequired {
    t.Fatalf("expected ErrSecretRequired, got %v", err)
  }
}

func TestValidateToken_ParsesValidToken(t *testing.T) {
  cfg := token.Config{
    Secret:   []byte("validsecret"),
    TTL:      time.Hour,
    Issuer:   "svc-issuer",
    Audience: "svc-audience",
  }
  claims := token.Claims{}

  s, err := token.GenerateToken(cfg, claims)
  if err != nil {
    t.Fatalf("GenerateToken failed: %v", err)
  }

  parsed, err := token.ValidateToken(cfg, s)
  if err != nil {
    t.Fatalf("ValidateToken failed: %v", err)
  }
  if parsed.IssuedAt == nil || parsed.ExpiresAt == nil {
    t.Fatalf("expected times to be set")
  }
  if parsed.Issuer != cfg.Issuer {
    t.Fatalf("expected issuer %q, got %q", cfg.Issuer, parsed.Issuer)
  }
  if len(parsed.Audience) == 0 || parsed.Audience[0] != cfg.Audience {
    t.Fatalf("expected audience %q, got %v", cfg.Audience, parsed.Audience)
  }
}

func TestValidateToken_WrongSecretFails(t *testing.T) {
  genCfg := token.Config{
    Secret: []byte("secret-a"),
    TTL:    time.Hour,
  }
  s, err := token.GenerateToken(genCfg, token.Claims{})
  if err != nil {
    t.Fatalf("GenerateToken failed: %v", err)
  }

  badCfg := token.Config{Secret: []byte("secret-b")}
  _, err = token.ValidateToken(badCfg, s)
  if err == nil {
    t.Fatalf("expected error validating with wrong secret")
  }
}

func TestValidateToken_EnforcesIssuerAndAudience(t *testing.T) {
  genCfg := token.Config{
    Secret: []byte("ia-secret"),
    TTL:    time.Hour,
  }
  now := time.Now()
  exp := jwt.NewNumericDate(now.Add(2 * time.Hour))
  providedIssuer := "provided-iss"
  providedAudience := jwt.ClaimStrings{"a", "b"}

  claims := token.Claims{
    RegisteredClaims: jwt.RegisteredClaims{
      Issuer:    providedIssuer,
      Audience:  providedAudience,
      ExpiresAt: exp,
    },
  }

  s, err := token.GenerateToken(genCfg, claims)
  if err != nil {
    t.Fatalf("GenerateToken failed: %v", err)
  }

  // Mismatched issuer should fail
  cfgMismatch := token.Config{Secret: genCfg.Secret, Issuer: "other-iss"}
  if _, err := token.ValidateToken(cfgMismatch, s); err == nil {
    t.Fatalf("expected issuer mismatch to fail")
  }

  // Mismatched audience should fail
  cfgMismatch = token.Config{Secret: genCfg.Secret, Audience: "other-aud"}
  if _, err := token.ValidateToken(cfgMismatch, s); err == nil {
    t.Fatalf("expected audience mismatch to fail")
  }

  // Matching issuer and audience should succeed
  cfgMatch := token.Config{Secret: genCfg.Secret, Issuer: providedIssuer, Audience: providedAudience[0]}
  parsed, err := token.ValidateToken(cfgMatch, s)
  if err != nil {
    t.Fatalf("expected validation to succeed, got %v", err)
  }
  if parsed.Issuer != providedIssuer {
    t.Fatalf("expected issuer %q, got %q", providedIssuer, parsed.Issuer)
  }
  if len(parsed.Audience) != len(providedAudience) || parsed.Audience[0] != providedAudience[0] {
    t.Fatalf("expected audience %v, got %v", providedAudience, parsed.Audience)
  }
}