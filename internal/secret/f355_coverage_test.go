package secret

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

type f355FailingReader struct{}

func (f355FailingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestF355EncryptionUsesFreshNoncesAndRejectsWrongKeys(t *testing.T) {
	t.Parallel()

	firstKey, err := NewFieldEncryptor("first encryption key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(first): %v", err)
	}
	secondKey, err := NewFieldEncryptor("second encryption key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(second): %v", err)
	}

	first, err := firstKey.Encrypt("same plaintext")
	if err != nil {
		t.Fatalf("Encrypt(first): %v", err)
	}
	second, err := firstKey.Encrypt("same plaintext")
	if err != nil {
		t.Fatalf("Encrypt(second): %v", err)
	}
	if first == second {
		t.Fatal("Encrypt() reused a nonce for identical plaintext")
	}
	if _, err := secondKey.Decrypt(first); err == nil {
		t.Fatal("Decrypt() with a different key succeeded")
	}
}

func TestF355EncryptReportsNonceEntropyFailure(t *testing.T) {
	originalReader := rand.Reader
	rand.Reader = f355FailingReader{}
	t.Cleanup(func() { rand.Reader = originalReader })

	encryptor, err := NewFieldEncryptor("encryption key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(): %v", err)
	}
	if _, err := encryptor.Encrypt("sensitive value"); err == nil || !strings.Contains(err.Error(), "generate nonce") {
		t.Fatalf("Encrypt() error = %v, want nonce generation failure", err)
	}
}
