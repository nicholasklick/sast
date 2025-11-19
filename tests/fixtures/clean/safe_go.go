// Clean Go code with no vulnerabilities
package safe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Safe SQL Query - Prepared statement
func GetUserByID(db *sql.DB, userID int) (string, error) {
	query := "SELECT name FROM users WHERE id = ?"
	var name string
	err := db.QueryRow(query, userID).Scan(&name)
	return name, err
}

// Safe File Access - Path validation
func ReadFile(filename string) (string, error) {
	basePath := "/var/data"
	fullPath := filepath.Join(basePath, filename)
	cleanPath := filepath.Clean(fullPath)

	if !strings.HasPrefix(cleanPath, basePath) {
		return "", fmt.Errorf("path traversal detected")
	}

	data, err := os.ReadFile(cleanPath)
	return string(data), err
}

// Safe Configuration
func GetAPIKey() (string, error) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("API_KEY not set")
	}
	return apiKey, nil
}

// Safe Cryptography - AES-GCM
func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, data, nil), nil
}

// Safe Hashing - SHA-256
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Safe Random Generation
func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// Safe Input Validation
func ValidateAndSanitize(input string) string {
	// Only allow alphanumeric, underscore, and hyphen
	var result strings.Builder
	for _, r := range input {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
