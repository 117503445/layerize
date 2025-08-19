package main

import (
	"os"
	"testing"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/internal/utils"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestCalculateFileSHA256(t *testing.T) {
	// 初始化 zerolog
	goutils.InitZeroLog()

	// 测试使用现有的 ./tmp/diff.tar.gz 文件
	hash, err := utils.CalculateFileSHA256("./tmp/diff.tar.gz")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// 验证哈希值不为空且长度正确 (SHA256 应该是 64 个字符)
	assert.Len(t, hash, 64)
	log.Info().Str("hash", hash).Msg("CalculateFileSHA256")

	// 创建一个临时文件用于测试
	content := "Hello, World!"
	tmpfile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// 写入测试内容
	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	// 计算文件的 SHA256
	hash, err = utils.CalculateFileSHA256(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// 验证哈希值是否正确 (已知的 "Hello, World!" 的 SHA256)
	expectedHash := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	assert.Equal(t, expectedHash, hash)

	// 测试不存在的文件
	_, err = utils.CalculateFileSHA256("non-existent-file.txt")
	assert.Error(t, err)
}
