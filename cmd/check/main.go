package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/117503445/goutils"
	"github.com/rs/zerolog/log"
)

// OCIImageLayout represents the OCI image layout file structure
type OCIImageLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// OCIManifest represents the OCI image manifest
type OCIManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"layers"`
}

func main() {
	goutils.InitZeroLog()
	
	ctx := context.Background()
	logger := log.Ctx(ctx)

	imagePath := "./tmp/diff"
    logger.Info().
        Str("phase", "inspect").
        Int("step", 0).
        Str("image_path", imagePath).
        Msg("Start validating local OCI image directory")
	
    // Step 1: Check if image directory exists
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		logger.Error().Str("path", imagePath).Msg("OCI image directory does not exist")
		os.Exit(1)
	}
    logger.Info().Str("phase", "inspect").Int("step", 1).Str("path", imagePath).Msg("Confirmed image directory exists")

    // Step 2: Check oci-layout file
	ociLayoutPath := filepath.Join(imagePath, "oci-layout")
	layoutData, err := os.ReadFile(ociLayoutPath)
	if err != nil {
		logger.Error().Err(err).Str("path", ociLayoutPath).Msg("Failed to read oci-layout file")
		os.Exit(1)
	}

	var ociLayout OCIImageLayout
	if err := json.Unmarshal(layoutData, &ociLayout); err != nil {
		logger.Error().Err(err).Msg("Failed to parse oci-layout file")
		os.Exit(1)
	}

    logger.Info().
        Str("phase", "inspect").
        Int("step", 2).
        Str("path", ociLayoutPath).
        Str("imageLayoutVersion", ociLayout.ImageLayoutVersion).
        Msg("Read oci-layout (image layout description)")

    // Step 3: Check index.json file
	indexJSONPath := filepath.Join(imagePath, "index.json")
	indexData, err := os.ReadFile(indexJSONPath)
	if err != nil {
		logger.Error().Err(err).Str("path", indexJSONPath).Msg("Failed to read index.json file")
		os.Exit(1)
	}

	var index struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int    `json:"size"`
		} `json:"manifests"`
	}

	if err := json.Unmarshal(indexData, &index); err != nil {
		logger.Error().Err(err).Msg("Failed to parse index.json file")
		os.Exit(1)
	}

    logger.Info().
        Str("phase", "inspect").
        Int("step", 3).
        Str("path", indexJSONPath).
        Int("schemaVersion", index.SchemaVersion).
        Int("manifestsCount", len(index.Manifests)).
        Msg("Parsed index.json (index file)")

    // Step 4: Check manifest file
	if len(index.Manifests) == 0 {
		logger.Error().Msg("No manifests found in index.json")
		os.Exit(1)
	}

	manifestDigest := index.Manifests[0].Digest
	if len(manifestDigest) < 7 || manifestDigest[:7] != "sha256:" {
		logger.Error().Str("digest", manifestDigest).Msg("Invalid manifest digest format")
		os.Exit(1)
	}

	manifestFileName := manifestDigest[7:] // Remove "sha256:" prefix
	manifestPath := filepath.Join(imagePath, "blobs", "sha256", manifestFileName)
	
    manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		logger.Error().Err(err).Str("path", manifestPath).Msg("Failed to read manifest file")
		os.Exit(1)
	}

	var manifest OCIManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		logger.Error().Err(err).Msg("Failed to parse manifest file")
		os.Exit(1)
	}

    logger.Info().
        Str("phase", "inspect").
        Int("step", 4).
        Str("path", manifestPath).
        Int("schemaVersion", manifest.SchemaVersion).
        Str("mediaType", manifest.MediaType).
        Str("configDigest", manifest.Config.Digest).
        Int("configSize", manifest.Config.Size).
        Int("layersCount", len(manifest.Layers)).
        Msg("Parsed manifest (image manifest)")

    // Step 5: Check config file
	configDigest := manifest.Config.Digest
	if len(configDigest) < 7 || configDigest[:7] != "sha256:" {
		logger.Error().Str("digest", configDigest).Msg("Invalid config digest format")
		os.Exit(1)
	}

	configFileName := configDigest[7:] // Remove "sha256:" prefix
	configPath := filepath.Join(imagePath, "blobs", "sha256", configFileName)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Error().Str("path", configPath).Msg("Config file does not exist")
		os.Exit(1)
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		logger.Error().Err(err).Str("path", configPath).Msg("Failed to read config file")
		os.Exit(1)
	}

    logger.Info().
        Str("phase", "inspect").
        Int("step", 5).
        Str("path", configPath).
        Str("configDigest", configDigest).
        Int("configSize", len(configData)).
        Msg("Validated config (image config file)")

    // Step 6: Check layer files
	for i, layer := range manifest.Layers {
		layerDigest := layer.Digest
		if len(layerDigest) < 7 || layerDigest[:7] != "sha256:" {
			logger.Error().Str("digest", layerDigest).Int("layerIndex", i).Msg("Invalid layer digest format")
			os.Exit(1)
		}

		layerFileName := layerDigest[7:] // Remove "sha256:" prefix
		layerPath := filepath.Join(imagePath, "blobs", "sha256", layerFileName)

		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			logger.Error().Str("path", layerPath).Int("layerIndex", i).Msg("Layer file does not exist")
			os.Exit(1)
		}

		layerData, err := os.ReadFile(layerPath)
		if err != nil {
			logger.Error().Err(err).Str("path", layerPath).Int("layerIndex", i).Msg("Failed to read layer file")
			os.Exit(1)
		}

		if len(layerData) != layer.Size {
			logger.Error().
				Int("expectedSize", layer.Size).
				Int("actualSize", len(layerData)).
				Int("layerIndex", i).
				Msg("Layer file size mismatch")
			os.Exit(1)
		}

        logger.Info().
            Str("phase", "inspect").
            Int("step", 6).
            Int("layerIndex", i).
            Str("path", layerPath).
            Str("mediaType", layer.MediaType).
            Str("digest", layer.Digest).
            Int("size", len(layerData)).
            Msg("Validated layer file")
	}

    logger.Info().Str("phase", "inspect").Int("step", 7).Msg("OCI image local validation completed")
}