package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
)

// MapToTar converts file mapping to tar format byte array
func MapToTar(ctx context.Context, files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("failed to write tar header: %w", err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("failed to write tar content: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	return buf.Bytes(), nil
}

// DecompressGzipData decompresses gzip data
func DecompressGzipData(ctx context.Context, data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return decompressedData, nil
}