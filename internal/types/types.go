package types

import (
	"io"
)

// Auth stores authentication information
type Auth struct {
	Username string
	Password string
}

// BuildImageParams stores parameters for BuildImage function
type BuildImageParams struct {
	BaseImageName   string
	BaseImageAuth   Auth
	DiffTarGzReader io.Reader
	DiffTarLen      int64
    // DiffTarSHA256 is the SHA256 of the uncompressed diff.tar (diffID without the sha256: prefix)
    DiffTarSHA256   string
    // DiffTarGzSHA256 is the SHA256 of the compressed diff.tar.gz blob (without the sha256: prefix)
    DiffTarGzSHA256 string
	TargetImage     string
	TargetAuth      Auth
	BaseImageTag    string
	TargetImageTag  string
}