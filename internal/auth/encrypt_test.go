package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestFieldEncryptorInactivePassesValuesThrough(t *testing.T) {
	t.Parallel()

	encryptor, err := NewFieldEncryptor("")
	if err != nil {
		t.Fatalf("NewFieldEncryptor() error = %v", err)
	}
	if encryptor.Active() {
		t.Fatal("inactive encryptor reports Active() = true")
	}

	encrypted, err := encryptor.Encrypt("plain-token")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if encrypted != "plain-token" {
		t.Fatalf("Encrypt() = %q, want plaintext passthrough", encrypted)
	}

	decrypted, err := encryptor.Decrypt("legacy-token")
	if err != nil {
		t.Fatalf("Decrypt(legacy) error = %v", err)
	}
	if decrypted != "legacy-token" {
		t.Fatalf("Decrypt(legacy) = %q, want plaintext passthrough", decrypted)
	}
}

func TestFieldEncryptorRoundTripAndRandomNonce(t *testing.T) {
	t.Parallel()

	encryptor, err := NewFieldEncryptor("test encryption key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor() error = %v", err)
	}
	if !encryptor.Active() {
		t.Fatal("configured encryptor reports Active() = false")
	}

	first, err := encryptor.Encrypt("secret-token")
	if err != nil {
		t.Fatalf("Encrypt(first) error = %v", err)
	}
	second, err := encryptor.Encrypt("secret-token")
	if err != nil {
		t.Fatalf("Encrypt(second) error = %v", err)
	}
	if first == second {
		t.Fatal("Encrypt() produced identical ciphertexts for the same plaintext")
	}
	for _, encrypted := range []string{first, second} {
		if !strings.HasPrefix(encrypted, encryptedPrefix) {
			t.Fatalf("ciphertext %q missing %q prefix", encrypted, encryptedPrefix)
		}
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt(%q) error = %v", encrypted, err)
		}
		if decrypted != "secret-token" {
			t.Fatalf("Decrypt() = %q, want original plaintext", decrypted)
		}
	}
}

func TestFieldEncryptorRejectsEncryptedValueWithoutKey(t *testing.T) {
	t.Parallel()

	active, err := NewFieldEncryptor("configured")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(active) error = %v", err)
	}
	encrypted, err := active.Encrypt("secret-token")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	inactive, err := NewFieldEncryptor("")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(inactive) error = %v", err)
	}
	if _, err := inactive.Decrypt(encrypted); err == nil || !strings.Contains(err.Error(), "no encryption key") {
		t.Fatalf("Decrypt(encrypted without key) error = %v, want missing-key error", err)
	}
}

func TestFieldEncryptorDecryptValidationErrors(t *testing.T) {
	t.Parallel()

	encryptor, err := NewFieldEncryptor("configured")
	if err != nil {
		t.Fatalf("NewFieldEncryptor() error = %v", err)
	}

	if got, err := encryptor.Encrypt(""); err != nil || got != "" {
		t.Fatalf("Encrypt(empty) = %q, %v; want empty nil", got, err)
	}
	if got, err := encryptor.Decrypt(""); err != nil || got != "" {
		t.Fatalf("Decrypt(empty) = %q, %v; want empty nil", got, err)
	}
	if _, err := encryptor.Decrypt(encryptedPrefix + "not-base64"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("Decrypt(invalid base64) error = %v, want decode error", err)
	}
	short := encryptedPrefix + base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := encryptor.Decrypt(short); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("Decrypt(short ciphertext) error = %v, want too-short error", err)
	}
}
