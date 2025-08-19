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
	// Initialize zerolog
	goutils.InitZeroLog()

	// Test using existing ./tmp/diff.tar.gz file
	hash, err := utils.CalculateFileSHA256("./tmp/diff.tar.gz")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify hash is not empty and has correct length (SHA256 should be 64 characters)
	assert.Len(t, hash, 64)
	log.Info().Str("hash", hash).Msg("CalculateFileSHA256")

	// Create a temporary file for testing
	content := "Hello, World!"
	tmpfile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// Write test content
	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	// Calculate file SHA256
	hash, err = utils.CalculateFileSHA256(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify if hash is correct (known SHA256 of "Hello, World!")
	expectedHash := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	assert.Equal(t, expectedHash, hash)

	// Test non-existent file
	_, err = utils.CalculateFileSHA256("non-existent-file.txt")
	assert.Error(t, err)
}
