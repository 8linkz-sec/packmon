package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordReturnsValidBcryptHash(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	// bcrypt hashes always start with "$2a$" or "$2b$".
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Fatalf("hash %q does not look like bcrypt", hash)
	}

	// Verify the hash is valid bcrypt by comparing against the original.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("hunter2")); err != nil {
		t.Fatalf("bcrypt.CompareHashAndPassword failed: %v", err)
	}
}

func TestHashPasswordUsesConfiguredCost(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost returned error: %v", err)
	}

	if cost != bcryptCost {
		t.Fatalf("bcrypt cost = %d, want %d", cost, bcryptCost)
	}
}

func TestCheckPasswordSucceedsWithCorrectPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if !CheckPassword(hash, "correct-password") {
		t.Fatal("CheckPassword returned false for correct password")
	}
}

func TestCheckPasswordFailsWithWrongPassword(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if CheckPassword(hash, "wrong-password") {
		t.Fatal("CheckPassword returned true for wrong password")
	}
}

func TestHashPasswordWithEmptyString(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword with empty string returned error: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword with empty string returned empty hash")
	}

	// The empty-string hash should validate against empty string.
	if !CheckPassword(hash, "") {
		t.Fatal("CheckPassword returned false for empty password matching empty hash")
	}

	// And reject a non-empty password.
	if CheckPassword(hash, "not-empty") {
		t.Fatal("CheckPassword returned true for non-empty password against empty hash")
	}
}

func TestCheckPasswordWithEmptyHashReturnsFalse(t *testing.T) {
	t.Parallel()

	if CheckPassword("", "any-password") {
		t.Fatal("CheckPassword returned true for empty hash")
	}
}

func TestCheckPasswordWithInvalidHashReturnsFalse(t *testing.T) {
	t.Parallel()

	if CheckPassword("not-a-bcrypt-hash", "password") {
		t.Fatal("CheckPassword returned true for invalid hash")
	}
}

func TestHashPasswordProducesDifferentHashesForSameInput(t *testing.T) {
	t.Parallel()

	hash1, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword(1) returned error: %v", err)
	}

	hash2, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword(2) returned error: %v", err)
	}

	if hash1 == hash2 {
		t.Fatal("two HashPassword calls with same input produced identical hashes (salt should differ)")
	}

	// Both should still validate.
	if !CheckPassword(hash1, "same-password") {
		t.Fatal("hash1 does not validate")
	}
	if !CheckPassword(hash2, "same-password") {
		t.Fatal("hash2 does not validate")
	}
}
