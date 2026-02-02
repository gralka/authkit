# authkit

A humble, minimal Go library for small projects that need simple password hashing
and token (JWT-like) handling. Designed to be clear, well-tested, and easy to
embed into other apps — not a full-featured auth framework.

### Why "humble"?
- Focuses on a narrow scope (password utilities + token helpers).
- Small, readable code; intended for learning and light production use.
- Includes tests for core functionality so you can trust the basics.

### Contents
- password: utilities for hashing and verifying passwords ([password/password.go](password/password.go)).
- token: token creation and verification helpers ([token/token.go](token/token.go)).
- middleware: HTTP middleware helpers for validating tokens and attaching claims to request context ([middleware/jwt.go](middleware/jwt.go)).

## Quickstart

### Prerequisites
- Go 1.18+ installed

### Installation

Clone the repository and run tests:

```bash
git clone https://github.com/gralka/authkit.git
cd authkit
go test ./...
```

### Usage

Import the packages you need and use the exposed helpers. Examples are
kept intentionally small — see the package files for full details.

Example (pseudo):

```go
import (
    "github.com/gralka/authkit/password"
    "github.com/gralka/authkit/token"
    "github.com/gralka/authkit/middleware"
)

// Hash a password
hash, err := password.Hash("secret123")

// Verify it
ok := password.Verify(hash, "secret123")

// Create and validate tokens with the token package
_ = token

// Protect an HTTP handler with RequireJWT
cfg := token.Config{
    Secret: []byte("my-secret"),
    TTL:    time.Hour,
}

protected := middleware.RequireJWT(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.GetClaims(r)
    if !ok {
        http.Error(w, "missing claims", http.StatusForbidden)
        return
    }

    _ = claims
    w.WriteHeader(http.StatusOK)
}))
```

### Testing

Run the test suite:

```bash
go test ./...
```

## Contributing

Contributions are welcome. If you see an improvement, open an issue or a pull
request. Keep changes small and focused; write tests for behavioral changes.

## License

Licensed under the MIT License. See [LICENSE](LICENSE).