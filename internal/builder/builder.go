package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/internal/config"
	"github.com/117503445/layerize/internal/manifest"
	"github.com/117503445/layerize/internal/registry"
	"github.com/117503445/layerize/internal/types"
	"github.com/117503445/layerize/internal/utils"
	"github.com/rs/zerolog/log"
)

// BuildImageFromMap creates a tar from file mapping, compresses it to tar.gz, and then builds an image
func BuildImageFromMap(files map[string][]byte, targetImage string, targetAuth types.Auth, baseImageName string, baseImageAuth types.Auth, baseImageTag string, targetImageTag string) error {
	// Create tar byte array using MapToTar
	tarData, err := utils.MapToTar(files)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create tar data")
		return fmt.Errorf("failed to create tar data: %w", err)
	}

	// Compress to tar.gz format
	var gzData bytes.Buffer
	gzWriter := gzip.NewWriter(&gzData)
	if _, err := gzWriter.Write(tarData); err != nil {
		log.Error().Err(err).Msg("Failed to write gzip data")
		return fmt.Errorf("failed to write gzip data: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		log.Error().Err(err).Msg("Failed to close gzip writer")
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Call BuildImage
	params := types.BuildImageParams{
		BaseImageName:   baseImageName,
		BaseImageAuth:   baseImageAuth,
		DiffTarGzReader: bytes.NewReader(gzData.Bytes()),
		DiffTarLen:      int64(gzData.Len()),
		TargetImage:     targetImage,
		TargetAuth:      targetAuth,
		BaseImageTag:    baseImageTag,
		TargetImageTag:  targetImageTag,
	}

	return BuildImage(params)
}

// BuildImage encapsulates the complete image building process
// Parameters:
// - params: BuildImageParams struct containing all parameters needed to build the image
func BuildImage(params types.BuildImageParams) error {
	goutils.InitZeroLog()

	// Get the content of diff.tar
	diffTarGzData, err := io.ReadAll(params.DiffTarGzReader)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read diffTarGzReader")
		return err
	}

	// Decompress diffTarGzData to get uncompressed data
	diffTarData, err := utils.DecompressGzipData(diffTarGzData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decompress diffTar data")
		return err
	}

	// Calculate SHA256 of uncompressed diff.tar to use as diffID
	diffSha256sum, err := utils.CalculateDataSHA256(diffTarData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to calculate diff.tar SHA256")
		return err
	}

	// Create temporary file for upload
	tmpFile, err := os.CreateTemp("", "diff.tar.gz")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temporary file")
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write the compressed diffTarData directly to the temporary file
	if _, err := tmpFile.Write(diffTarGzData); err != nil {
		log.Error().Err(err).Msg("Failed to write to temporary file")
		return err
	}

	// If we need to reposition the file pointer to the beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		log.Error().Err(err).Msg("Failed to reset file pointer")
		return err
	}

	// Get compressed file information
	fileSize := params.DiffTarLen

	// Reopen the file for upload
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		log.Error().Err(err).Msg("Failed to reopen temporary file")
		return err
	}
	defer file.Close()

	// Calculate SHA256 of the compressed file
	sha256sum, err := utils.CalculateFileSHA256(tmpFile.Name())
	if err != nil {
		log.Error().Err(err).Msg("Failed to calculate compressed file SHA256")
		return err
	}

	// Upload layer to target image registry
	err = registry.UploadLayerToRegistryWithAuth(file, sha256sum, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("UploadLayerToRegistryWithAuth failed")
		return err
	}

	log.Info().Msg("File upload completed")

	// Declare updatedConfig variable
	var updatedConfig []byte

	// Determine base image tag
	baseImageTag := "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// Get base image configuration information
	baseConfig, err := registry.GetConfigWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get config")
		return err
	}

	log.Info().Int("configSize", len(baseConfig)).Msg("Successfully obtained config")
	log.Debug().RawJSON("config", baseConfig).Msg("Config content")

	// Call UpdateOCIConfig to update config, using diff.tar's sha256 as diffID
	updatedConfig, err = manifest.UpdateOCIConfig(baseConfig, "sha256:"+diffSha256sum)
	if err != nil {
		log.Error().Err(err).Msg("Failed to update config")
		return err
	}

	log.Info().Int("updatedConfigSize", len(updatedConfig)).Msg("Successfully updated config")
	log.Debug().RawJSON("updatedConfig", updatedConfig).Msg("Updated config content")

	// Upload the updated config
	err = config.UploadUpdatedConfigToRegistry(updatedConfig, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload updated config")
		return err
	}

	log.Info().Msg("Successfully uploaded updated config")

	// Determine base image tag
	baseImageTag = "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// Get base image manifest example
	manifestData, contentType, err := registry.GetManifestWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get manifest")
		return err
	}

	log.Info().Str("contentType", contentType).Int("manifestSize", len(manifestData)).Msg("Successfully obtained manifest")
	// If you need to view the manifest content, you can uncomment the following line
	log.Debug().RawJSON("manifest", manifestData).Msg("Manifest content")

	// Calculate SHA256 digest of the updated config
	configSHA256, err := utils.CalculateDataSHA256(updatedConfig)
	if err != nil {
		log.Error().Err(err).Msg("Failed to calculate config SHA256")
		return err
	}
	configDigest := "sha256:" + configSHA256

	// Update config reference in manifest
	var manifestDataObj map[string]any
	if err := json.Unmarshal(manifestData, &manifestDataObj); err != nil {
		log.Error().Err(err).Msg("Failed to parse manifest")
		return err
	}

	if configSection, ok := manifestDataObj["config"].(map[string]any); ok {
		configSection["digest"] = configDigest
		// Recalculate config size
		configSection["size"] = len(updatedConfig)
	}

	// Reserialize manifest
	updatedManifestWithNewConfig, err := json.Marshal(manifestDataObj)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize updated manifest")
		return err
	}

	// Call updateOCIManifest to update manifest
	updatedManifest, err := manifest.UpdateOCIManifest(updatedManifestWithNewConfig, "sha256:"+sha256sum, fileSize, "")
	if err != nil {
		log.Error().Err(err).Msg("Failed to update manifest")
		return err
	}

	log.Info().Int("updatedManifestSize", len(updatedManifest)).Msg("Successfully updated manifest")
	log.Debug().RawJSON("updatedManifest", updatedManifest).Msg("Updated manifest content")

	// Determine target image tag
	targetImageTag := "latest"
	if params.TargetImageTag != "" {
		targetImageTag = params.TargetImageTag
	}

	// Upload the updated manifest to the target registry
	client := registry.NewClient("https://registry.cn-hangzhou.aliyuncs.com", params.TargetAuth.Username, params.TargetAuth.Password)
	err = client.UploadManifest(context.Background(), params.TargetImage, targetImageTag, updatedManifest, contentType)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload updated manifest")
		return err
	}

	log.Info().Msg("Successfully uploaded updated manifest")
	return nil
}