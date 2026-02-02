package password_test

import (
	"testing"

	"github.com/gralka/authkit/password"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := password.Hash("secret123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	if !password.Verify(hash, "secret123") {
		t.Fatal("expected password to verify")
	}

	if password.Verify(hash, "wrongpassword") {
		t.Fatal("expected verification to fail")
	}
}
