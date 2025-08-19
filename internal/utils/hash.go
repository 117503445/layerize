package utils

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// calculateFileSHA256 计算文件的 SHA256 哈希值
func CalculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("计算哈希失败: %w", err)
	}

	// 返回小写的哈希值
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// calculateDataSHA256 计算字节数据的 SHA256 哈希值
func CalculateDataSHA256(data []byte) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		return "", fmt.Errorf("计算哈希失败: %w", err)
	}

	// 返回小写的哈希值
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}