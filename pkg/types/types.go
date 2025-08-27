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
//
// BaseImage and TargetImage should be full references in the form
// "repository[:tag]". If tag is omitted, it defaults to "latest".
type BuildImageParams struct {
	// BaseImage is the base image reference (e.g., "namespace/repo:tag")
	BaseImage       string
	BaseImageAuth   Auth
	DiffTarGzReader io.Reader
	DiffTarGzLen    int64
	// DiffTarSHA256 is the SHA256 of the uncompressed diff.tar (diffID without the sha256: prefix)
	DiffTarSHA256 string
	// DiffTarGzSHA256 is the SHA256 of the compressed diff.tar.gz blob (without the sha256: prefix)
	DiffTarGzSHA256 string
	// TargetImage is the target image reference (e.g., "namespace/repo:tag")
	TargetImage string
	TargetAuth  Auth
}

// SyncBlobsParams stores parameters for SyncBlobs function
type SyncBlobsParams struct {
	// BaseImage is the base image reference (e.g., "namespace/repo:tag")
	BaseImage     string
	BaseImageAuth Auth
	// TargetImage is the target image reference (e.g., "namespace/repo:tag")
	TargetImage string
	TargetAuth  Auth
}
