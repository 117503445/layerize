package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

// calculateFileSHA256 计算指定文件的 SHA256 哈希值
func calculateFileSHA256(filePath string) (string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Str("path", filePath).Msg("无法打开文件")
		return "", fmt.Errorf("无法打开文件 %s: %w", filePath, err)
	}
	defer file.Close()

	// 创建一个新的 SHA256 hasher
	hasher := sha256.New()

	// 将文件内容复制到 hasher
	if _, err := io.Copy(hasher, file); err != nil {
		log.Error().Err(err).Str("path", filePath).Msg("读取文件时出错")
		return "", fmt.Errorf("读取文件 %s 时出错: %w", filePath, err)
	}

	// 计算哈希值并返回十六进制表示
	hashBytes := hasher.Sum(nil)
	return fmt.Sprintf("%x", hashBytes), nil
}

// calculateDataSHA256 计算数据的 SHA256 哈希值
func calculateDataSHA256(data []byte) (string, error) {
	// 创建一个新的 SHA256 hasher
	hasher := sha256.New()

	// 将数据复制到 hasher
	if _, err := io.Copy(hasher, bytes.NewReader(data)); err != nil {
		log.Error().Err(err).Msg("计算数据SHA256时出错")
		return "", fmt.Errorf("计算数据SHA256时出错: %w", err)
	}

	// 计算哈希值并返回十六进制表示
	hashBytes := hasher.Sum(nil)
	return fmt.Sprintf("%x", hashBytes), nil
}