package token

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}
