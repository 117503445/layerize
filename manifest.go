package main

import (
	"encoding/json"
	"fmt"
)

// MediaType constants
const (
	MediaTypeDockerManifest   = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeOCIManifest      = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeDockerLayer      = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	MediaTypeOCILayer         = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// Common base struct for both manifest types
type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type ManifestLayer struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// Docker v2 Manifest (Schema 2)
type DockerManifestV2 struct {
	SchemaVersion int              `json:"schemaVersion"`
	MediaType     string           `json:"mediaType,omitempty"`
	Config        ManifestConfig   `json:"config"`
	Layers        []ManifestLayer  `json:"layers"`
}

// OCI Image Manifest
type OCIManifest struct {
	MediaType     string           `json:"mediaType"`
	SchemaVersion int              `json:"schemaVersion"`
	Config        ManifestConfig   `json:"config"`
	Layers        []ManifestLayer  `json:"layers"`
}

// UpdateManifest adds a new layer to the manifest.
// It detects whether the manifest is Docker v2 or OCI and handles accordingly.
func UpdateManifest(originalManifest []byte, newLayerDigest string, newLayerSize int64, mediaType string) ([]byte, string, error) {
	// Detect manifest type by MediaType
	var generic struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(originalManifest, &generic); err != nil {
		return nil, "", fmt.Errorf("failed to parse manifest mediaType: %w", err)
	}

	var newManifest []byte
	var err error

	switch generic.MediaType {
	case MediaTypeDockerManifest:
		newManifest, err = updateDockerManifestV2(originalManifest, newLayerDigest, newLayerSize, mediaType)
	case MediaTypeOCIManifest:
		newManifest, err = updateOCIManifest(originalManifest, newLayerDigest, newLayerSize, mediaType)
	default:
		return nil, "", fmt.Errorf("unsupported manifest mediaType: %s", generic.MediaType)
	}

	if err != nil {
		return nil, "", err
	}

	return newManifest, generic.MediaType, nil
}

// updateDockerManifestV2 handles Docker v2 Schema 2 manifest
func updateDockerManifestV2(original []byte, digest string, size int64, mediaType string) ([]byte, error) {
	var manifest DockerManifestV2
	if err := json.Unmarshal(original, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal docker manifest: %w", err)
	}

	// Set default mediaType if not provided
	if mediaType == "" {
		mediaType = MediaTypeDockerLayer
	}

	// Append new layer
	newLayer := ManifestLayer{
		MediaType: mediaType,
		Digest:    digest,
		Size:      size,
	}
	manifest.Layers = append(manifest.Layers, newLayer)

	// Re-encode
	return json.MarshalIndent(manifest, "", "  ")
}

// updateOCIManifest handles OCI Image Manifest
func updateOCIManifest(original []byte, digest string, size int64, mediaType string) ([]byte, error) {
	var manifest OCIManifest
	if err := json.Unmarshal(original, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OCI manifest: %w", err)
	}

	// Set default mediaType if not provided
	if mediaType == "" {
		mediaType = MediaTypeOCILayer
	}

	// Append new layer
	newLayer := ManifestLayer{
		MediaType: mediaType,
		Digest:    digest,
		Size:      size,
	}
	manifest.Layers = append(manifest.Layers, newLayer)

	// Re-encode
	return json.MarshalIndent(manifest, "", "  ")
}