package auth

import "github.com/8linkz-sec/packmon/internal/secret"

const encryptedPrefix = secret.EncryptedPrefix

// FieldEncryptor is retained for existing auth-package callers. The
// implementation lives in internal/secret so storage code does not depend on
// admin authentication.
type FieldEncryptor = secret.FieldEncryptor

// NewFieldEncryptor creates a neutral field encryptor.
func NewFieldEncryptor(rawKey string) (*FieldEncryptor, error) {
	return secret.NewFieldEncryptor(rawKey)
}
