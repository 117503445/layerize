package main

import (
	"encoding/json"
	"fmt"
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

	imagePath := "./tmp/diff"
	
	// Check if image directory exists
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		log.Error().Str("path", imagePath).Msg("OCI image directory does not exist")
		os.Exit(1)
	}

	// Check oci-layout file
	ociLayoutPath := filepath.Join(imagePath, "oci-layout")
	layoutData, err := os.ReadFile(ociLayoutPath)
	if err != nil {
		log.Error().Err(err).Str("path", ociLayoutPath).Msg("Failed to read oci-layout file")
		os.Exit(1)
	}

	var ociLayout OCIImageLayout
	if err := json.Unmarshal(layoutData, &ociLayout); err != nil {
		log.Error().Err(err).Msg("Failed to parse oci-layout file")
		os.Exit(1)
	}

	log.Info().Str("version", ociLayout.ImageLayoutVersion).Msg("OCI image layout version")

	// Check index.json file
	indexJSONPath := filepath.Join(imagePath, "index.json")
	indexData, err := os.ReadFile(indexJSONPath)
	if err != nil {
		log.Error().Err(err).Str("path", indexJSONPath).Msg("Failed to read index.json file")
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
		log.Error().Err(err).Msg("Failed to parse index.json file")
		os.Exit(1)
	}

	log.Info().Int("schemaVersion", index.SchemaVersion).Int("manifestsCount", len(index.Manifests)).Msg("Index file info")

	// Check manifest file
	if len(index.Manifests) == 0 {
		log.Error().Msg("No manifests found in index.json")
		os.Exit(1)
	}

	manifestDigest := index.Manifests[0].Digest
	if len(manifestDigest) < 7 || manifestDigest[:7] != "sha256:" {
		log.Error().Str("digest", manifestDigest).Msg("Invalid manifest digest format")
		os.Exit(1)
	}

	manifestFileName := manifestDigest[7:] // Remove "sha256:" prefix
	manifestPath := filepath.Join(imagePath, "blobs", "sha256", manifestFileName)
	
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		log.Error().Err(err).Str("path", manifestPath).Msg("Failed to read manifest file")
		os.Exit(1)
	}

	var manifest OCIManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		log.Error().Err(err).Msg("Failed to parse manifest file")
		os.Exit(1)
	}

	log.Info().
		Int("schemaVersion", manifest.SchemaVersion).
		Str("mediaType", manifest.MediaType).
		Str("configDigest", manifest.Config.Digest).
		Int("configSize", manifest.Config.Size).
		Int("layersCount", len(manifest.Layers)).
		Msg("Manifest info")

	// Check config file
	configDigest := manifest.Config.Digest
	if len(configDigest) < 7 || configDigest[:7] != "sha256:" {
		log.Error().Str("digest", configDigest).Msg("Invalid config digest format")
		os.Exit(1)
	}

	configFileName := configDigest[7:] // Remove "sha256:" prefix
	configPath := filepath.Join(imagePath, "blobs", "sha256", configFileName)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Error().Str("path", configPath).Msg("Config file does not exist")
		os.Exit(1)
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		log.Error().Err(err).Str("path", configPath).Msg("Failed to read config file")
		os.Exit(1)
	}

	log.Info().Int("configSize", len(configData)).Msg("Config file checked")

	// Check layer files
	for i, layer := range manifest.Layers {
		layerDigest := layer.Digest
		if len(layerDigest) < 7 || layerDigest[:7] != "sha256:" {
			log.Error().Str("digest", layerDigest).Int("layerIndex", i).Msg("Invalid layer digest format")
			os.Exit(1)
		}

		layerFileName := layerDigest[7:] // Remove "sha256:" prefix
		layerPath := filepath.Join(imagePath, "blobs", "sha256", layerFileName)

		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			log.Error().Str("path", layerPath).Int("layerIndex", i).Msg("Layer file does not exist")
			os.Exit(1)
		}

		layerData, err := os.ReadFile(layerPath)
		if err != nil {
			log.Error().Err(err).Str("path", layerPath).Int("layerIndex", i).Msg("Failed to read layer file")
			os.Exit(1)
		}

		if len(layerData) != layer.Size {
			log.Error().
				Int("expectedSize", layer.Size).
				Int("actualSize", len(layerData)).
				Int("layerIndex", i).
				Msg("Layer file size mismatch")
			os.Exit(1)
		}

		log.Info().
			Int("layerIndex", i).
			Str("mediaType", layer.MediaType).
			Str("digest", layer.Digest).
			Int("size", len(layerData)).
			Msg("Layer checked")
	}

	log.Info().Msg("OCI image check completed successfully")
	fmt.Println("OCI image check completed successfully")
}