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
	"github.com/117503445/layerize/internal/manifest"
	"github.com/117503445/layerize/internal/registry"
	"github.com/117503445/layerize/internal/types"
	"github.com/117503445/layerize/internal/utils"
	"github.com/rs/zerolog/log"
)

// BuildImageFromMap creates a tar from file mapping, compresses it to tar.gz, and then builds an image
func BuildImageFromMap(ctx context.Context, files map[string][]byte, targetImage string, targetAuth types.Auth, baseImageName string, baseImageAuth types.Auth, baseImageTag string, targetImageTag string) error {
	logger := log.Ctx(ctx)
	
	// Create tar byte array using MapToTar
	tarData, err := utils.MapToTar(ctx, files)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create tar data")
		return fmt.Errorf("failed to create tar data: %w", err)
	}

	// Compress to tar.gz format
	var gzData bytes.Buffer
	gzWriter := gzip.NewWriter(&gzData)
	if _, err := gzWriter.Write(tarData); err != nil {
		logger.Error().Err(err).Msg("Failed to write gzip data")
		return fmt.Errorf("failed to write gzip data: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		logger.Error().Err(err).Msg("Failed to close gzip writer")
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

	return BuildImage(ctx, params)
}

// BuildImage encapsulates the complete image building process
// Parameters:
// - params: BuildImageParams struct containing all parameters needed to build the image
func BuildImage(ctx context.Context, params types.BuildImageParams) error {
	logger := log.Ctx(ctx)
	goutils.InitZeroLog()

    logger.Info().
        Str("phase", "build").
        Int("step", 0).
        Str("base_image", params.BaseImageName).
        Str("target_image", params.TargetImage).
        Str("base_tag", params.BaseImageTag).
        Str("target_tag", params.TargetImageTag).
        Int64("diff_tar_gz_len", params.DiffTarLen).
        Msg("Start image building process")

	// Create centralized registry clients for token reuse
	registryURL := "https://registry.cn-hangzhou.aliyuncs.com"
	targetClient := registry.NewClient(registryURL, params.TargetAuth.Username, params.TargetAuth.Password)
	// baseClient for future use if needed for base image operations with different credentials
	_ = registry.NewClient(registryURL, params.BaseImageAuth.Username, params.BaseImageAuth.Password)

	// Get the content of diff.tar
    diffTarGzData, err := io.ReadAll(params.DiffTarGzReader)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read diffTarGzReader")
		return err
	}
    logger.Info().Str("phase", "build").Int("step", 1).Int("gz_size", len(diffTarGzData)).Msg("Read compressed differential layer data")

	// Decompress diffTarGzData to get uncompressed data
    diffTarData, err := utils.DecompressGzipData(ctx, diffTarGzData)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to decompress diffTar data")
		return err
	}
    logger.Info().Str("phase", "build").Int("step", 2).Int("tar_size", len(diffTarData)).Msg("Decompressed differential layer to diff.tar data")

	// Calculate SHA256 of uncompressed diff.tar to use as diffID
    diffSha256sum, err := utils.CalculateDataSHA256(ctx, diffTarData)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate diff.tar SHA256")
		return err
	}
    logger.Info().Str("phase", "build").Int("step", 3).Str("diff_id", "sha256:"+diffSha256sum).Msg("Calculated SHA256 of diff.tar (diffID)")

	// Create temporary file for upload
    tmpFile, err := os.CreateTemp("", "diff.tar.gz")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create temporary file")
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write the compressed diffTarData directly to the temporary file
    if _, err := tmpFile.Write(diffTarGzData); err != nil {
		logger.Error().Err(err).Msg("Failed to write to temporary file")
		return err
	}
    logger.Info().Str("phase", "build").Int("step", 4).Str("tmp_file", tmpFile.Name()).Int("bytes_written", len(diffTarGzData)).Msg("Written compressed layer to temporary file")

	// If we need to reposition the file pointer to the beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		logger.Error().Err(err).Msg("Failed to reset file pointer")
		return err
	}

	// Get compressed file information
    fileSize := params.DiffTarLen
    logger.Info().Str("phase", "build").Int("step", 5).Int64("compressed_size", fileSize).Msg("Get compressed layer size")

	// Reopen the file for upload
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		logger.Error().Err(err).Msg("Failed to reopen temporary file")
		return err
	}
	defer file.Close()

	// Calculate SHA256 of the compressed file
    sha256sum, err := utils.CalculateFileSHA256(ctx, tmpFile.Name())
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate compressed file SHA256")
		return err
	}
    logger.Info().Str("phase", "build").Int("step", 6).Str("layer_digest", "sha256:"+sha256sum).Msg("Calculated compressed layer SHA256")

	// Upload layer to target image registry using centralized client
    err = registry.UploadLayerWithClient(targetClient, file, sha256sum, params.TargetImage)
	if err != nil {
		logger.Error().Err(err).Msg("UploadLayerWithClient failed")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 7).Msg("Uploaded compressed layer to target image registry")

	// Declare updatedConfig variable
	var updatedConfig []byte

	// Determine base image tag
	baseImageTag := "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// Get base image configuration information
    baseConfig, err := registry.GetConfigWithAuth(ctx, registryURL, params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 8).Int("configSize", len(baseConfig)).Msg("Obtained base image config")
    logger.Debug().RawJSON("config", baseConfig).Msg("Base image config content")

	// Call UpdateOCIConfig to update config, using diff.tar's sha256 as diffID
    updatedConfig, err = manifest.UpdateOCIConfig(ctx, baseConfig, "sha256:"+diffSha256sum)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 9).Int("updatedConfigSize", len(updatedConfig)).Msg("Updated base image config, added new layer diffID")
    logger.Debug().RawJSON("updatedConfig", updatedConfig).Msg("Updated config content")

	// Upload the updated config using centralized client
	// Calculate SHA256 digest of the updated config (for upload)
    uploadConfigSHA256, err := utils.CalculateDataSHA256(ctx, updatedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate config SHA256 for upload")
		return err
	}
	uploadConfigDigest := "sha256:" + uploadConfigSHA256
	
    err = registry.UploadConfigWithClient(targetClient, updatedConfig, uploadConfigDigest, params.TargetImage)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to upload updated config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 10).Str("config_digest", uploadConfigDigest).Msg("Uploaded updated config")

	// Determine base image tag
	baseImageTag = "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// Get base image manifest example
    manifestData, contentType, err := registry.GetManifestWithAuth(ctx, registryURL, params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get manifest")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 11).Str("contentType", contentType).Int("manifestSize", len(manifestData)).Msg("Obtained base image manifest")
    logger.Debug().RawJSON("manifest", manifestData).Msg("Base image manifest content")

	// Calculate SHA256 digest of the updated config
    configSHA256, err := utils.CalculateDataSHA256(ctx, updatedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate config SHA256")
		return err
	}
	configDigest := "sha256:" + configSHA256

	// Update config reference in manifest
	var manifestDataObj map[string]any
	if err := json.Unmarshal(manifestData, &manifestDataObj); err != nil {
		logger.Error().Err(err).Msg("Failed to parse manifest")
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
		logger.Error().Err(err).Msg("Failed to serialize updated manifest")
		return err
	}

	// Call updateOCIManifest to update manifest
    updatedManifest, err := manifest.UpdateOCIManifest(ctx, updatedManifestWithNewConfig, "sha256:"+sha256sum, fileSize, "")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update manifest")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 12).Int("updatedManifestSize", len(updatedManifest)).Msg("Updated manifest, pointing to new config and layer")
    logger.Debug().RawJSON("updatedManifest", updatedManifest).Msg("Updated manifest content")

	// Determine target image tag
	targetImageTag := "latest"
	if params.TargetImageTag != "" {
		targetImageTag = params.TargetImageTag
	}

	// Upload the updated manifest to the target registry using existing client
    err = targetClient.UploadManifest(ctx, params.TargetImage, targetImageTag, updatedManifest, contentType)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to upload updated manifest")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 13).Str("repository", params.TargetImage).Str("reference", targetImageTag).Msg("Uploaded updated manifest to target registry")
	return nil
}