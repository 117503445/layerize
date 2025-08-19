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
	TargetImage     string
	TargetAuth      Auth
	BaseImageTag    string
	TargetImageTag  string
}