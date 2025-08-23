package utils

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateDataSHA256(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "empty",
			data:     []byte(""),
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			data:     []byte("Hello, World!"),
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := CalculateDataSHA256(context.Background(), tc.data)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
			assert.Len(t, result, 64)
		})
	}
}

func TestCalculateFileSHA256(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		content     string
		wantErr     bool
		expected    string
		useRealFile bool
	}{
		{
			name:     "empty file",
			content:  "",
			wantErr:  false,
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world file",
			content:  "Hello, World!",
			wantErr:  false,
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:    "non-existent file",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr && tc.content == "" {
				_, err := CalculateFileSHA256(context.Background(), "this/file/does/not/exist")
				assert.Error(t, err)
				return
			}

			tmpFile, err := os.CreateTemp("", "hash-test-*")
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tc.content)
			assert.NoError(t, err)
			assert.NoError(t, tmpFile.Close())

			result, err := CalculateFileSHA256(context.Background(), tmpFile.Name())
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
			assert.Len(t, result, 64)
		})
	}
}
