package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// MapToTar converts a map of file paths to file contents into a tar archive
func MapToTar(files map[string][]byte) ([]byte, error) {
	// Create a buffer to write our archive to
	buf := new(bytes.Buffer)

	// Create a new tar archive
	tw := tar.NewWriter(buf)
	defer tw.Close()

	// Add each file to the archive
	for filePath, fileContent := range files {
		// Create a new header
		hdr := &tar.Header{
			Name: filePath,
			Mode: 0600,
			Size: int64(len(fileContent)),
		}

		// Write the header
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}

		// Write the file content
		if _, err := tw.Write(fileContent); err != nil {
			return nil, err
		}
	}

	// Close the tar writer to flush any remaining data
	if err := tw.Close(); err != nil {
		return nil, err
	}

	// Return the tar data as bytes
	return buf.Bytes(), nil
}

// DecompressGzipData 解压缩gzip数据
func DecompressGzipData(data []byte) ([]byte, error) {
	// 创建gzip reader
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("创建gzip reader失败: %w", err)
	}
	defer reader.Close()

	// 读取解压缩后的数据
	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("读取解压缩数据失败: %w", err)
	}

	return decompressedData, nil
}