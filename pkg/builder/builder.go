package builder

import (
    "bytes"
    "compress/gzip"
    "context"
    "encoding/json"
    "fmt"
    "strings"

    "github.com/117503445/goutils"
    "github.com/117503445/layerize/pkg/manifest"
    "github.com/117503445/layerize/pkg/registry"
    "github.com/117503445/layerize/pkg/types"
    "github.com/117503445/layerize/pkg/utils"
    "github.com/rs/zerolog/log"
)

// BuildImageFromMap creates a tar from file mapping, compresses it to tar.gz, and then builds an image
// Parameters:
// - ctx: context for the operation
// - files: map of file paths to file content bytes
// - targetImage: the target image reference (repository[:tag])
// - targetAuth: authentication information for the target registry
// - baseImage: the base image reference (repository[:tag])
// - baseImageAuth: authentication information for the base image registry
// Returns:
// - error: any error that occurred during the build process
func BuildImageFromMap(ctx context.Context, files map[string][]byte, targetImage string, targetAuth types.Auth, baseImage string, baseImageAuth types.Auth) error {
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

    // Calculate hashes for both uncompressed and compressed data
    diffTarSHA256, err := utils.CalculateDataSHA256(ctx, tarData)
    if err != nil {
        logger.Error().Err(err).Msg("Failed to calculate diff.tar SHA256")
        return err
    }
    diffTarGzSHA256, err := utils.CalculateDataSHA256(ctx, gzData.Bytes())
    if err != nil {
        logger.Error().Err(err).Msg("Failed to calculate diff.tar.gz SHA256")
        return err
    }

    // Call BuildImage
    params := types.BuildImageParams{
        BaseImage:       baseImage,
        BaseImageAuth:   baseImageAuth,
        DiffTarGzReader: bytes.NewReader(gzData.Bytes()),
        DiffTarLen:      int64(gzData.Len()),
        DiffTarSHA256:   diffTarSHA256,
        DiffTarGzSHA256: diffTarGzSHA256,
        TargetImage:     targetImage,
        TargetAuth:      targetAuth,
    }

	return BuildImage(ctx, params)
}

// BuildImage encapsulates the complete image building process
// Parameters:
// - ctx: context for the operation
// - params: BuildImageParams struct containing all parameters needed to build the image
// Returns:
// - error: any error that occurred during the build process
func BuildImage(ctx context.Context, params types.BuildImageParams) error {
	logger := log.Ctx(ctx)
	goutils.InitZeroLog()

    // Parse image references, extracting registry URL, repository, and tag
    baseRegistryURL, baseRepository, baseTag := parseImageReference(params.BaseImage)
    targetRegistryURL, targetRepository, targetTag := parseImageReference(params.TargetImage)

    logger.Info().
        Str("phase", "build").
        Int("step", 0).
        Str("base_image", baseRepository).
        Str("target_image", targetRepository).
        Str("base_tag", baseTag).
        Str("target_tag", targetTag).
        Int64("diff_tar_gz_len", params.DiffTarLen).
        Msg("Start image building process")

    // Create centralized registry clients for token reuse, per registry
    logger.Info().
        Str("target_registry", targetRegistryURL).
        Str("base_registry", baseRegistryURL).
        Msg("Resolved registries from image references")

    targetClient := registry.NewClient(targetRegistryURL, params.TargetAuth.Username, params.TargetAuth.Password)
    // Reuse client only if registry and credentials are identical
    baseClient := targetClient
    if baseRegistryURL != targetRegistryURL ||
        params.BaseImageAuth.Username != params.TargetAuth.Username ||
        params.BaseImageAuth.Password != params.TargetAuth.Password {
        baseClient = registry.NewClient(baseRegistryURL, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
    }

    // Use provided digests and size without decompressing or temp files
    fileSize := params.DiffTarLen
    logger.Info().Str("phase", "build").Int("step", 1).Int64("compressed_size", fileSize).Msg("Using provided compressed layer size")

    // Upload layer to target image registry using centralized client (streaming reader)
    err := registry.UploadLayerWithClient(ctx, targetClient, params.DiffTarGzReader, params.DiffTarGzSHA256, targetRepository)
	if err != nil {
		logger.Error().Err(err).Msg("UploadLayerWithClient failed")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 2).Msg("Uploaded compressed layer to target image registry")

	// Declare updatedConfig variable
	var updatedConfig []byte

	// Get base image configuration information
    // Pull manifest then blob via client so one token is fetched and reused
    manifestData, contentType, err := baseClient.GetManifest(ctx, baseRepository, baseTag)
    if err != nil {
        logger.Error().Err(err).Msg("Failed to get base manifest via client")
        return err
    }
    var manifestObj map[string]any
    if err := json.Unmarshal(manifestData, &manifestObj); err != nil {
        logger.Error().Err(err).Msg("Failed to parse base manifest")
        return err
    }
    configDigest, _ := manifestObj["config"].(map[string]any)["digest"].(string)
    if configDigest == "" {
        return fmt.Errorf("config digest not found in manifest")
    }
    baseConfig, err := baseClient.GetBlob(ctx, baseRepository, configDigest)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 3).Int("configSize", len(baseConfig)).Msg("Obtained base image config")
    logger.Debug().RawJSON("config", baseConfig).Msg("Base image config content")

    // Call UpdateOCIConfig to update config, using provided diff.tar sha256 as diffID
    updatedConfig, err = manifest.UpdateOCIConfig(ctx, baseConfig, "sha256:"+params.DiffTarSHA256)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 4).Int("updatedConfigSize", len(updatedConfig)).Msg("Updated base image config, added new layer diffID")
    logger.Debug().RawJSON("updatedConfig", updatedConfig).Msg("Updated config content")

	// Upload the updated config using centralized client
	// Calculate SHA256 digest of the updated config (for upload)
    uploadConfigSHA256, err := utils.CalculateDataSHA256(ctx, updatedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate config SHA256 for upload")
		return err
	}
	uploadConfigDigest := "sha256:" + uploadConfigSHA256
	
    err = registry.UploadConfigWithClient(ctx, targetClient, updatedConfig, uploadConfigDigest, targetRepository)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to upload updated config")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 5).Str("config_digest", uploadConfigDigest).Msg("Uploaded updated config")

    // We already have base manifest and contentType from earlier call using baseClient
    logger.Info().Str("phase", "build").Int("step", 6).Str("contentType", contentType).Int("manifestSize", len(manifestData)).Msg("Obtained base image manifest")
    logger.Debug().RawJSON("manifest", manifestData).Msg("Base image manifest content")

	// Calculate SHA256 digest of the updated config
    configSHA256, err := utils.CalculateDataSHA256(ctx, updatedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate config SHA256")
		return err
	}
    configDigest = "sha256:" + configSHA256

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

    // Call updateOCIManifest to update manifest using provided compressed blob digest
    updatedManifest, err := manifest.UpdateOCIManifest(ctx, updatedManifestWithNewConfig, "sha256:"+params.DiffTarGzSHA256, fileSize, "")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to update manifest")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 7).Int("updatedManifestSize", len(updatedManifest)).Msg("Updated manifest, pointing to new config and layer")
    logger.Debug().RawJSON("updatedManifest", updatedManifest).Msg("Updated manifest content")

	// Upload the updated manifest to the target registry using existing client
    err = targetClient.UploadManifest(ctx, targetRepository, targetTag, updatedManifest, contentType)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to upload updated manifest")
		return err
	}

    logger.Info().Str("phase", "build").Int("step", 8).Str("repository", targetRepository).Str("reference", targetTag).Msg("Uploaded updated manifest to target registry")
	return nil
}

// splitRepositoryAndTag splits an image reference into repository and tag.
// If no tag is present, tag defaults to "latest".
// It is careful to not confuse registry port (e.g., my-registry:5000) with tag by
// only considering the last ':' after the last '/'.
func splitRepositoryAndTag(reference string) (repository string, tag string) {
    if reference == "" {
        return "", "latest"
    }
    // Strip any digest part if provided (repo@sha256:...)
    // For this project we do not support digest references for upload targets,
    // but handle gracefully by removing the digest part.
    atIndex := -1
    for i := 0; i < len(reference); i++ {
        if reference[i] == '@' {
            atIndex = i
            break
        }
    }
    ref := reference
    if atIndex != -1 {
        ref = reference[:atIndex]
    }

    // Find last '/' and then check for ':' after that
    lastSlash := -1
    for i := len(ref) - 1; i >= 0; i-- {
        if ref[i] == '/' {
            lastSlash = i
            break
        }
    }
    lastColon := -1
    for i := len(ref) - 1; i >= 0; i-- {
        if ref[i] == ':' {
            lastColon = i
            break
        }
    }

    if lastColon != -1 && lastColon > lastSlash {
        return ref[:lastColon], ref[lastColon+1:]
    }
    return ref, "latest"
}

// parseImageReference splits an image reference into registry URL, repository (without registry), and tag.
// Supported formats:
// - "registry.example.com/namespace/repo:tag"
// - "localhost:5000/namespace/repo:tag"
// - "namespace/repo:tag" (no explicit registry; falls back to defaultRegistryURL)
// The returned registryURL always has an https:// scheme and no trailing slash.
func parseImageReference(reference string) (registryURL string, repository string, tag string) {
    if reference == "" {
        return defaultRegistryURL(), "", "latest"
    }

    // Strip any digest part if provided (repo@sha256:...)
    ref := reference
    if idx := strings.IndexByte(ref, '@'); idx != -1 {
        ref = ref[:idx]
    }

    // Determine tag by finding the last ':' that appears after the last '/'
    lastSlash := strings.LastIndexByte(ref, '/')
    lastColon := strings.LastIndexByte(ref, ':')
    if lastColon != -1 && lastColon > lastSlash {
        repository = ref[:lastColon]
        tag = ref[lastColon+1:]
    } else {
        repository = ref
        tag = "latest"
    }

    // Detect registry host (first path component) if it looks like a registry
    firstSlash := strings.IndexByte(repository, '/')
    var registryHost string
    if firstSlash != -1 {
        first := repository[:firstSlash]
        if looksLikeRegistryHost(first) {
            registryHost = first
            repository = repository[firstSlash+1:]
        }
    } else {
        // Single component like "repo" or "repo:tag" with no namespace
        // No explicit registry
    }

    if registryHost == "" {
        registryURL = defaultRegistryURL()
    } else if strings.HasPrefix(registryHost, "http://") || strings.HasPrefix(registryHost, "https://") {
        registryURL = strings.TrimRight(registryHost, "/")
    } else {
        registryURL = "https://" + registryHost
    }

    // Normalize repository (remove any accidental leading '/')
    repository = strings.TrimLeft(repository, "/")
    return registryURL, repository, tag
}

// looksLikeRegistryHost returns true if s resembles a registry host (has '.' or ':' or is localhost)
func looksLikeRegistryHost(s string) bool {
    if s == "localhost" || strings.HasPrefix(s, "localhost:") {
        return true
    }
    return strings.Contains(s, ".") || strings.Contains(s, ":")
}

// defaultRegistryURL returns the fallback registry URL when the image reference has no explicit registry
func defaultRegistryURL() string {
    // Default to Docker Hub registry
    return "https://registry-1.docker.io"
}