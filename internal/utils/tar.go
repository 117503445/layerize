package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// MapToTar 将文件映射转换为 tar 格式的字节数组
func MapToTar(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("写入 tar header 失败: %w", err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("写入 tar 内容失败: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("关闭 tar writer 失败: %w", err)
	}

	return buf.Bytes(), nil
}

// DecompressGzipData 解压缩 gzip 数据
func DecompressGzipData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("创建 gzip reader 失败: %w", err)
	}
	defer gzipReader.Close()

	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("读取解压缩数据失败: %w", err)
	}

	return decompressedData, nil
}