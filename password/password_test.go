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

func TestHashWithCostAndCost(t *testing.T) {
	cost := 8
	hash, err := password.HashWithCost("secret123", cost)
	if err != nil {
		t.Fatalf("hash with cost failed: %v", err)
	}

	gotCost, err := password.Cost(hash)
	if err != nil {
		t.Fatalf("cost failed: %v", err)
	}
	if gotCost != cost {
		t.Fatalf("expected cost %d, got %d", cost, gotCost)
	}
}
