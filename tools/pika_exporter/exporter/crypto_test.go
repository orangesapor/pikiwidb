package exporter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptPassword(t *testing.T) {
	key := PadKey("my16charkey12345")
	plaintext := "7bb34209"

	encrypted, err := EncryptPassword(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("EncryptPassword returned empty string")
	}

	if encrypted == plaintext {
		t.Fatal("EncryptPassword returned plaintext unchanged")
	}

	decrypted, err := DecryptPassword(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptPassword failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("DecryptPassword returned wrong value: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmptyPassword(t *testing.T) {
	key := PadKey("my16charkey12345")

	encrypted, err := EncryptPassword("", key)
	if err != nil {
		t.Fatalf("EncryptPassword for empty string failed: %v", err)
	}
	if encrypted != "" {
		t.Fatalf("EncryptPassword for empty string should return empty, got %q", encrypted)
	}

	decrypted, err := DecryptPassword("", key)
	if err != nil {
		t.Fatalf("DecryptPassword for empty string failed: %v", err)
	}
	if decrypted != "" {
		t.Fatalf("DecryptPassword for empty string should return empty, got %q", decrypted)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := PadKey("my16charkey12345")
	key2 := PadKey("another16charkey")

	plaintext := "7bb34209"
	encrypted, err := EncryptPassword(plaintext, key1)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	_, err = DecryptPassword(encrypted, key2)
	if err == nil {
		t.Fatal("DecryptPassword with wrong key should fail but succeeded")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	key := PadKey("my16charkey12345")

	_, err := DecryptPassword("not-valid-base64!!!", key)
	if err == nil {
		t.Fatal("DecryptPassword with invalid base64 should fail but succeeded")
	}
}

func TestDecryptTooShortCiphertext(t *testing.T) {
	key := PadKey("my16charkey12345")

	// base64 of a single byte "AA==" which is too short for GCM
	_, err := DecryptPassword("AA==", key)
	if err == nil {
		t.Fatal("DecryptPassword with too short ciphertext should fail but succeeded")
	}
}

func TestPadKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"short key padded to 16", "abc", 16},
		{"8 char key padded to 16", "8charkey!", 16},
		{"16 char key stays 16", "my16charkey12345", 16},
		{"20 char key padded to 24", "20characterkey!!!", 24},
		{"24 char key stays 24", "24characterkey123456", 24},
		{"28 char key padded to 32", "28characterkey12345678", 32},
		{"32 char key stays 32", "32characterkey1234567890ab", 32},
		{"40 char key truncated to 32", "40characterkey1234567890abcdefghij", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := PadKey(tt.input)
			if len(padded) != tt.expected {
				t.Errorf("PadKey(%q) = key of length %d, want %d", tt.input, len(padded), tt.expected)
			}
		})
	}
}

func TestReadPasswordFile(t *testing.T) {
	// Create a temporary password file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "passwords.txt")

	content := `# This is a comment
password1

password2
# Another comment
password3
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	passwords, err := ReadPasswordFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadPasswordFile failed: %v", err)
	}

	expected := []string{"password1", "password2", "password3"}
	if len(passwords) != len(expected) {
		t.Fatalf("ReadPasswordFile returned %d passwords, want %d", len(passwords), len(expected))
	}

	for i, p := range expected {
		if passwords[i] != p {
			t.Errorf("passwords[%d] = %q, want %q", i, passwords[i], p)
		}
	}
}

func TestReadPasswordFileEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.txt")

	content := `# Only comments
# No passwords
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	_, err := ReadPasswordFile(tmpFile)
	if err == nil {
		t.Fatal("ReadPasswordFile with empty file should fail but succeeded")
	}
}

func TestReadPasswordFileNonExistent(t *testing.T) {
	_, err := ReadPasswordFile("/nonexistent/path/passwords.txt")
	if err == nil {
		t.Fatal("ReadPasswordFile with non-existent file should fail but succeeded")
	}
}

func TestResolvePasswordPlaintext(t *testing.T) {
	// Plaintext password without encryption key
	result, err := ResolvePassword("7bb34209", "", "")
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != "7bb34209" {
		t.Fatalf("ResolvePassword returned %q, want %q", result, "7bb34209")
	}
}

func TestResolvePasswordEncrypted(t *testing.T) {
	key := PadKey("my16charkey12345")
	plaintext := "7bb34209"

	encrypted, err := EncryptPassword(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	result, err := ResolvePassword(encrypted, "", key)
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != plaintext {
		t.Fatalf("ResolvePassword returned %q, want %q", result, plaintext)
	}
}

func TestResolvePasswordFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "passwords.txt")

	content := "7bb34209\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	result, err := ResolvePassword("", tmpFile, "")
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != "7bb34209" {
		t.Fatalf("ResolvePassword returned %q, want %q", result, "7bb34209")
	}
}

func TestResolvePasswordFileEncrypted(t *testing.T) {
	key := PadKey("my16charkey12345")
	plaintext := "7bb34209"

	encrypted, err := EncryptPassword(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "passwords.txt")

	content := encrypted + "\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	result, err := ResolvePassword("", tmpFile, key)
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != plaintext {
		t.Fatalf("ResolvePassword returned %q, want %q", result, plaintext)
	}
}

func TestResolvePasswordPriority(t *testing.T) {
	// Password file should take priority over command-line password
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "passwords.txt")

	content := "file_password\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	result, err := ResolvePassword("cmd_password", tmpFile, "")
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != "file_password" {
		t.Fatalf("ResolvePassword should use file password, got %q, want %q", result, "file_password")
	}
}

func TestResolvePasswordEmpty(t *testing.T) {
	result, err := ResolvePassword("", "", "")
	if err != nil {
		t.Fatalf("ResolvePassword failed: %v", err)
	}
	if result != "" {
		t.Fatalf("ResolvePassword returned %q, want empty string", result)
	}
}

func TestEncryptDecryptDifferentKeySizes(t *testing.T) {
	passwords := []string{"7bb34209", "complex_p@ssw0rd!", ""}
	keys := []string{"16charkey123456", "24charkey12345678901234", "32charkey12345678901234567890ab"}

	for _, pwd := range passwords {
		for _, keyStr := range keys {
			key := PadKey(keyStr)
			encrypted, err := EncryptPassword(pwd, key)
			if err != nil {
				t.Errorf("EncryptPassword(%q, key_of_len_%d) failed: %v", pwd, len(key), err)
				continue
			}

			decrypted, err := DecryptPassword(encrypted, key)
			if err != nil {
				t.Errorf("DecryptPassword(%q, key_of_len_%d) failed: %v", pwd, len(key), err)
				continue
			}

			if decrypted != pwd {
				t.Errorf("DecryptPassword(EncryptPassword(%q)) = %q, want %q (key_len=%d)", pwd, decrypted, pwd, len(key))
			}
		}
	}
}