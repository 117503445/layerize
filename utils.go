package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/rs/zerolog/log"
)

func compressToTarGz(sourceDir, outputTarGz string) error {
	// if err := compressToTarGz("tmp", "tmp.tar.gz"); err != nil {
	// 	log.Panic().Err(err).Msg("打包失败")
	// }

	// 检查源目录是否存在
	info, err := os.Stat(sourceDir)
	if os.IsNotExist(err) {
		log.Error().Str("path", sourceDir).Msg("源目录不存在")
		return fmt.Errorf("源目录不存在: %s", sourceDir)
	}
	if !info.IsDir() {
		log.Error().Str("path", sourceDir).Msg("源路径不是目录")
		return fmt.Errorf("源路径不是目录: %s", sourceDir)
	}

	log.Info().
		Str("source", sourceDir).
		Str("output", outputTarGz).
		Msg("compressToTarGz")

	// 构建 tar 命令
	// tar -czf output.tar.gz -C /path/to/source .
	cmd := exec.Command("tar", "-czf", outputTarGz, "-C", sourceDir, ".")

	// 捕获命令的标准输出和错误（可选）
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 执行命令
	err = cmd.Run()
	if err != nil {
		log.Error().
			Err(err).
			Str("command", cmd.String()).
			Msg("执行 tar 命令失败")
		return fmt.Errorf("执行 tar 命令失败: %w", err)
	}

	log.Info().
		Str("output", outputTarGz).
		Dur("duration", cmd.ProcessState.UserTime()).
		Msg("打包成功")

	return nil
}

// CalculateFileSHA256 计算指定文件的 SHA256 哈希值
func CalculateFileSHA256(filePath string) (string, error) {
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
