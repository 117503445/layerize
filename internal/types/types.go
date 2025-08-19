package types

import (
	"io"
)

// Auth 用于存储认证信息
type Auth struct {
	Username string
	Password string
}

// BuildImageParams 用于存储 BuildImage 函数的参数
type BuildImageParams struct {
	BaseImageName   string
	BaseImageAuth   Auth
	DiffTarGzReader io.Reader
	DiffTarLen      int64
	TargetImage     string
	TargetAuth      Auth
	BaseImageTag    string
	TargetImageTag  string
}