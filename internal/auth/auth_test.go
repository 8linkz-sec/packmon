package auth

import (
	"errors"
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

func TestHashPasswordRejectsPasswordOverBcryptLimit(t *testing.T) {
	t.Parallel()

	hash, err := HashPassword(strings.Repeat("p", 73))
	if err == nil {
		t.Fatal("HashPassword() error = nil, want bcrypt length error")
	}
	if !errors.Is(err, bcrypt.ErrPasswordTooLong) {
		t.Fatalf("HashPassword() error = %v, want bcrypt.ErrPasswordTooLong", err)
	}
	if hash != "" {
		t.Fatalf("HashPassword() hash = %q, want empty hash on error", hash)
	}
}

func TestValidateAdminPasswordCountsCharactersNotBytes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "eleven ASCII characters", password: strings.Repeat("a", 11), wantErr: true},
		{name: "twelve ASCII characters", password: strings.Repeat("a", 12)},
		// Four CJK runes are 12 bytes but only four characters.
		{name: "four multi-byte characters", password: strings.Repeat("一", 4), wantErr: true},
		{name: "eleven multi-byte characters", password: strings.Repeat("é", 11), wantErr: true},
		{name: "twelve multi-byte characters", password: strings.Repeat("一", 12)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateAdminPassword(tt.password)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("ValidateAdminPassword(%d runes, %d bytes) error = %v, want error %v", len([]rune(tt.password)), len(tt.password), err, tt.wantErr)
			}
		})
	}
}

// TestEqualizePasswordCheckUsesARealCostBcryptComparison keeps the dummy
// comparison as expensive as a real CheckPassword call: it must run against a
// valid hash with the production cost, or an unknown username would still
// answer faster than a wrong password.
func TestEqualizePasswordCheckUsesARealCostBcryptComparison(t *testing.T) {
	EqualizePasswordCheck("any-submitted-password")
	EqualizePasswordCheck(strings.Repeat("p", 100))

	cost, err := bcrypt.Cost(dummyPasswordHash)
	if err != nil {
		t.Fatalf("dummy hash is not a valid bcrypt hash: %v", err)
	}
	if cost != bcryptCost {
		t.Fatalf("dummy hash cost = %d, want bcryptCost %d", cost, bcryptCost)
	}
	if CheckPassword(string(dummyPasswordHash), "any-submitted-password") {
		t.Fatal("dummy hash matched a submitted password")
	}
}

// TestValidateAdminPasswordRejectsPasswordsOverBcryptLimit keeps the policy in
// step with bcrypt, which refuses more than MaxAdminPasswordBytes bytes. A
// longer password used to pass validation and then fail hashing, so a password
// change showed the generic update failure and bootstrap a hash error.
func TestValidateAdminPasswordRejectsPasswordsOverBcryptLimit(t *testing.T) {
	t.Parallel()

	if MaxAdminPasswordBytes != 72 {
		t.Fatalf("MaxAdminPasswordBytes = %d, want the bcrypt input limit 72", MaxAdminPasswordBytes)
	}
	for _, tt := range []struct {
		name     string
		password string
		wantErr  error
	}{
		{name: "72 ASCII bytes", password: strings.Repeat("a", 72)},
		{name: "73 ASCII bytes", password: strings.Repeat("a", 73), wantErr: ErrAdminPasswordTooLong},
		// 24 three-byte runes are exactly 72 bytes.
		{name: "72 multi-byte bytes", password: strings.Repeat("一", 24)},
		// 25 three-byte runes are only 25 characters but 75 bytes.
		{name: "75 multi-byte bytes", password: strings.Repeat("一", 25), wantErr: ErrAdminPasswordTooLong},
		{name: "too short", password: "short", wantErr: ErrAdminPasswordTooShort},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateAdminPassword(tt.password)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateAdminPassword(%d bytes) error = %v, want nil", len(tt.password), err)
				}
				if _, hashErr := HashPassword(tt.password); hashErr != nil {
					t.Fatalf("HashPassword(%d bytes) error = %v, want a password the policy accepts to hash", len(tt.password), hashErr)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateAdminPassword(%d bytes) error = %v, want %v", len(tt.password), err, tt.wantErr)
			}
		})
	}
	if errors.Is(ErrAdminPasswordTooLong, ErrAdminPasswordTooShort) || !strings.Contains(ErrAdminPasswordTooLong.Error(), "72 bytes") {
		t.Fatalf("ErrAdminPasswordTooLong = %v, want its own error naming the 72-byte maximum", ErrAdminPasswordTooLong)
	}
}
