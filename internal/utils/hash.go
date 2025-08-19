package utils

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// CalculateFileSHA256 calculates SHA256 hash of a file
func CalculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Return lowercase hash value
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// CalculateDataSHA256 calculates SHA256 hash of byte data
func CalculateDataSHA256(data []byte) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Return lowercase hash value
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}