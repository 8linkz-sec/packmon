package secret

import "testing"

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
