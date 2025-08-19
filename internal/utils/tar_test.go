package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapToTar(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		files    map[string][]byte
		expected map[string][]byte
	}{
		{
			name:     "empty map",
			files:    map[string][]byte{},
			expected: map[string][]byte{},
		},
		{
			name: "single file",
			files: map[string][]byte{
				"a.txt": []byte("alpha"),
			},
			expected: map[string][]byte{
				"a.txt": []byte("alpha"),
			},
		},
		{
			name: "multiple files",
			files: map[string][]byte{
				"a.txt": []byte("alpha"),
				"b.txt": []byte("beta"),
			},
			expected: map[string][]byte{
				"a.txt": []byte("alpha"),
				"b.txt": []byte("beta"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data, err := MapToTar(context.Background(), tc.files)
			assert.NoError(t, err)

			got := make(map[string][]byte)
			tr := tar.NewReader(bytes.NewReader(data))
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				assert.NoError(t, err)
				content, err := io.ReadAll(tr)
				assert.NoError(t, err)
				got[hdr.Name] = content
			}

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecompressGzipData(t *testing.T) {
	t.Parallel()

	t.Run("valid gzip", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, err := gw.Write([]byte("hello gzip"))
		assert.NoError(t, err)
		assert.NoError(t, gw.Close())

		output, err := DecompressGzipData(context.Background(), buf.Bytes())
		assert.NoError(t, err)
		assert.Equal(t, []byte("hello gzip"), output)
	})

	t.Run("invalid gzip", func(t *testing.T) {
		_, err := DecompressGzipData(context.Background(), []byte("not gzipped"))
		assert.Error(t, err)
	})
}
