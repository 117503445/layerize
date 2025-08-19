package config

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/117503445/layerize/internal/registry"
	"github.com/rs/zerolog/log"
)

// UploadUpdatedConfigToRegistry uploads updated config to registry
func UploadUpdatedConfigToRegistry(ctx context.Context, updatedConfig []byte, registryURL, repository, username, password string) error {
	// Calculate SHA256 digest of config
	hash := sha256.Sum256(updatedConfig)
	configDigest := fmt.Sprintf("sha256:%x", hash)

	log.Info().Str("configDigest", configDigest).Int("configSize", len(updatedConfig)).Msg("Starting to upload updated config")

	// Use registry package function to upload config
	err := registry.UploadConfigToRegistryWithAuth(ctx, updatedConfig, configDigest, registryURL, repository, username, password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload config")
		return fmt.Errorf("failed to upload config: %w", err)
	}

	log.Info().Msg("Config upload successful")
	return nil
}