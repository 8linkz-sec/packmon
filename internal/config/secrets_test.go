package config

import (
	"strings"
	"testing"
)

func TestGeneratedBase64KeyValidates(t *testing.T) {
	s := SecretSpec{Key: "PACKMON_ENCRYPTION_KEY", Kind: SecretBase64Bytes, Bytes: 32}
	v, err := s.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := s.Validate(v); err != nil {
		t.Fatalf("validate generated: %v", err)
	}
}

func TestValidateBase64Failures(t *testing.T) {
	s := SecretSpec{Key: "K", Kind: SecretBase64Bytes, Bytes: 32}
	if err := s.Validate(""); err == nil {
		t.Fatal("empty must fail")
	}
	if err := s.Validate("not base64 %%%"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("bad base64 err = %v", err)
	}
	short := s.Validate("YWJj") // "abc" -> 3 bytes
	if short == nil || !strings.Contains(short.Error(), "expected 32") {
		t.Fatalf("short err = %v", short)
	}
}

func TestValidateProductionSecretsAggregates(t *testing.T) {
	env := map[string]string{
		"PACKMON_SERVER_MODE":          "production",
		"PACKMON_ENCRYPTION_KEY":       "YWJj", // 3 bytes -> wrong length
		"PACKMON_ADMIN_AUDIT_HMAC_KEY": "",     // empty
	}
	err := ValidateProductionSecrets(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("want aggregated error")
	}
	msg := err.Error()
	for _, want := range []string{
		"PACKMON_ENCRYPTION_KEY",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY",
		"init-secrets",
		"Troubleshooting",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("aggregated error missing %q in:\n%s", want, msg)
		}
	}
}

func TestValidateProductionSecretsSkipsDevelopment(t *testing.T) {
	env := map[string]string{"PACKMON_SERVER_MODE": "development"}
	if err := ValidateProductionSecrets(func(k string) string { return env[k] }); err != nil {
		t.Fatalf("development must skip, got %v", err)
	}
}
