package secret

import (
	"strings"
	"testing"
)

func TestFieldEncryptorInactivePassesPlaintextThrough(t *testing.T) {
	encryptor, err := NewFieldEncryptor("")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(empty) error = %v", err)
	}
	if encryptor.Active() {
		t.Fatal("inactive encryptor reports active")
	}
	if got, err := encryptor.Encrypt("plain"); err != nil || got != "plain" {
		t.Fatalf("Encrypt inactive = %q, %v", got, err)
	}
	if got, err := encryptor.Decrypt("plain"); err != nil || got != "plain" {
		t.Fatalf("Decrypt legacy plaintext = %q, %v", got, err)
	}
	if _, err := encryptor.Decrypt(EncryptedPrefix + "abc"); err == nil || !strings.Contains(err.Error(), "no encryption key") {
		t.Fatalf("Decrypt encrypted without key error = %v", err)
	}
}

func TestFieldEncryptorRoundTripAndRejectsInvalidCiphertext(t *testing.T) {
	encryptor, err := NewFieldEncryptor("test-key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(key) error = %v", err)
	}
	if !encryptor.Active() {
		t.Fatal("active encryptor reports inactive")
	}
	if got, err := encryptor.Encrypt(""); err != nil || got != "" {
		t.Fatalf("Encrypt empty = %q, %v", got, err)
	}

	ciphertext, err := encryptor.Encrypt("secret-value")
	if err != nil {
		t.Fatalf("Encrypt active error = %v", err)
	}
	if !strings.HasPrefix(ciphertext, EncryptedPrefix) || strings.Contains(ciphertext, "secret-value") {
		t.Fatalf("ciphertext = %q, want encrypted prefix without plaintext", ciphertext)
	}
	plaintext, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt active error = %v", err)
	}
	if plaintext != "secret-value" {
		t.Fatalf("Decrypt = %q", plaintext)
	}

	for _, value := range []string{EncryptedPrefix + "not-base64!", EncryptedPrefix + "YQ==", ciphertext[:len(ciphertext)-1] + "A"} {
		t.Run(value, func(t *testing.T) {
			if _, err := encryptor.Decrypt(value); err == nil {
				t.Fatal("Decrypt invalid ciphertext error = nil")
			}
		})
	}
}
