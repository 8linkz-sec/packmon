package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// encryptedPrefix is prepended to ciphertext so that we can
	// distinguish encrypted values from legacy plaintext values during
	// the migration period.
	encryptedPrefix = "enc:"
)

// FieldEncryptor encrypts and decrypts short string values (e.g. API
// keys) using AES-256-GCM. If no encryption key is configured, it
// passes values through in plaintext and reports itself as inactive.
type FieldEncryptor struct {
	gcm    cipher.AEAD
	active bool
}

// NewFieldEncryptor creates a FieldEncryptor. If rawKey is empty, the
// encryptor is inactive and Encrypt/Decrypt become identity functions.
// The rawKey is stretched to exactly 32 bytes using SHA-256.
func NewFieldEncryptor(rawKey string) (*FieldEncryptor, error) {
	if rawKey == "" {
		return &FieldEncryptor{active: false}, nil
	}

	// Derive a 32-byte key from the raw input.
	keyHash := sha256.Sum256([]byte(rawKey))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("auth: new AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: new GCM: %w", err)
	}

	return &FieldEncryptor{gcm: gcm, active: true}, nil
}

// Active returns true if the encryptor has a configured key and will
// actually encrypt values.
func (e *FieldEncryptor) Active() bool {
	return e.active
}

// Encrypt returns the AES-256-GCM encrypted, base64-encoded form of
// plaintext, prefixed with "enc:". If the encryptor is inactive, the
// plaintext is returned unchanged. Empty strings are returned as-is.
func (e *FieldEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" || !e.active {
		return plaintext, nil
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("auth: generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt reverses Encrypt. If the value does not start with "enc:"
// it is assumed to be legacy plaintext and returned unchanged. This
// allows a seamless migration from unencrypted to encrypted storage.
func (e *FieldEncryptor) Decrypt(value string) (string, error) {
	if value == "" {
		return "", nil
	}

	if !strings.HasPrefix(value, encryptedPrefix) {
		// Legacy plaintext -- return as-is.
		return value, nil
	}

	if !e.active {
		return "", errors.New("auth: encrypted value found but no encryption key is configured (set PACKMON_ENCRYPTION_KEY)")
	}

	raw, err := base64.StdEncoding.DecodeString(value[len(encryptedPrefix):])
	if err != nil {
		return "", fmt.Errorf("auth: decode encrypted value: %w", err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("auth: encrypted value too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("auth: decrypt: %w", err)
	}

	return string(plaintext), nil
}
