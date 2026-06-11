package exporter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// EncryptPassword encrypts a plaintext password using AES-GCM with the given key.
// The key must be 16, 24, or 32 bytes long (AES-128, AES-192, AES-256).
// Returns a base64-encoded ciphertext.
func EncryptPassword(plaintext, key string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPassword decrypts a base64-encoded ciphertext using AES-GCM with the given key.
// The key must be 16, 24, or 32 bytes long (AES-128, AES-192, AES-256).
// Returns the plaintext password.
func DecryptPassword(encodedCipher, key string) (string, error) {
	if encodedCipher == "" {
		return "", nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCipher)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// ReadPasswordFile reads passwords from a file.
// The file format is one password per line.
// Lines starting with '#' are treated as comments and ignored.
// Empty lines are ignored.
func ReadPasswordFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read password file %s: %w", filePath, err)
	}

	var passwords []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		passwords = append(passwords, line)
	}

	if len(passwords) == 0 {
		return nil, fmt.Errorf("password file %s is empty or contains no valid entries", filePath)
	}

	return passwords, nil
}

// ResolvePassword resolves the password based on the provided parameters.
// Priority:
//  1. If passwordFile is set, read passwords from the file
//  2. If password is set and encryptionKey is set, decrypt the password
//  3. If password is set and encryptionKey is not set, use the password as-is (plaintext, backward compatible)
//  4. If nothing is set, return empty string
func ResolvePassword(password, passwordFile, encryptionKey string) (string, error) {
	// Priority 1: Read from password file
	if passwordFile != "" {
		passwords, err := ReadPasswordFile(passwordFile)
		if err != nil {
			return "", err
		}
		// If encryption key is provided, decrypt each password in the file
		if encryptionKey != "" {
			var decrypted []string
			for _, p := range passwords {
				dp, err := DecryptPassword(p, encryptionKey)
				if err != nil {
					return "", fmt.Errorf("failed to decrypt password from file: %w", err)
				}
				decrypted = append(decrypted, dp)
			}
			return strings.Join(decrypted, ","), nil
		}
		// No encryption key, treat passwords in file as plaintext
		return strings.Join(passwords, ","), nil
	}

	// Priority 2 & 3: Use command-line password
	if password != "" && encryptionKey != "" {
		// Decrypt the password
		decrypted, err := DecryptPassword(password, encryptionKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt password: %w", err)
		}
		return decrypted, nil
	}

	// Priority 4: Plaintext password (backward compatible)
	return password, nil
}

// PadKey pads or truncates the key to a valid AES key size (16, 24, or 32 bytes).
func PadKey(key string) string {
	keyBytes := []byte(key)
	keyLen := len(keyBytes)
	switch {
	case keyLen <= 16:
		padded := make([]byte, 16)
		copy(padded, keyBytes)
		return string(padded)
	case keyLen <= 24:
		padded := make([]byte, 24)
		copy(padded, keyBytes)
		return string(padded)
	case keyLen <= 32:
		padded := make([]byte, 32)
		copy(padded, keyBytes)
		return string(padded)
	default:
		return string(keyBytes[:32])
	}
}
