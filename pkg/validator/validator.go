package validator

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/117503445/goutils"
    "github.com/rs/zerolog/log"
)

// ValidateBuiltImage validates if the built image is correct by pulling the image and verifying its content
func ValidateBuiltImage(ctx context.Context, targetImage string, content string) error {
	logger := log.Ctx(ctx)

	logger.Info().Msg("verify image diff")

	// Extract registry from target image name
	registryPart := strings.Split(targetImage, "/")[0]
	logger.Info().
		Str("registry", registryPart).
		Str("TargetImageName", targetImage).
		Send()

	// Create temporary directories
	dirTempOci, err := os.MkdirTemp("", "devpod-test-oci")
	if err != nil {
		logger.Panic().Err(err).Send()
	}
	defer os.RemoveAll(dirTempOci)

	dirTempRootFs, err := os.MkdirTemp("", "devpod-test-rootfs")
	if err != nil {
		logger.Panic().Err(err).Send()
	}
	defer os.RemoveAll(dirTempRootFs)

    // Login to registry (prefer target_username/target_password for clarity)
    username := firstNonEmpty(os.Getenv("target_username"), os.Getenv("username"))
    password := firstNonEmpty(os.Getenv("target_password"), os.Getenv("password"))
	loginCmd := exec.CommandContext(ctx, "skopeo", "login", "--username", username, "--password", password, registryPart)
	loginOutput, err := loginCmd.CombinedOutput()
	if err != nil {
		logger.Error().Err(err).Str("output", string(loginOutput)).Msg("Failed to login to registry")
		return fmt.Errorf("failed to login to registry: %w", err)
	}

	// Copy image using skopeo
	copyCmd := exec.CommandContext(ctx, "skopeo", "copy", fmt.Sprintf("docker://%s", targetImage), fmt.Sprintf("oci://%s:latest", dirTempOci))
	copyOutput, err := copyCmd.CombinedOutput()
	if err != nil {
		logger.Error().Err(err).Str("output", string(copyOutput)).Msg("Failed to copy image")
		return fmt.Errorf("failed to copy image: %w", err)
	}

	// Unpack image using umoci
	unpackCmd := exec.CommandContext(ctx, "umoci", "unpack", "--rootless", "--image", dirTempOci, dirTempRootFs)
	unpackOutput, err := unpackCmd.CombinedOutput()
	if err != nil {
		logger.Error().Err(err).Str("output", string(unpackOutput)).Msg("Failed to unpack image")
		return fmt.Errorf("failed to unpack image: %w", err)
	}

	// Verify file content
	fileCreated := filepath.Join(dirTempRootFs, "rootfs", "new.txt")
	containerContent, err := goutils.ReadText(fileCreated)
	if err != nil {
		logger.Panic().Err(err).Send()
	}

	if content != containerContent {
		logger.Panic().
			Str("expected", content).
			Str("actual", containerContent).
			Msg("container content is not equal to expected")
	} else {
		logger.Info().
			Str("content", content).
			Msg("container content is equal to expected")
	}

	// Check that old.txt has been deleted (whiteout file)
	if goutils.FileExists(filepath.Join(dirTempRootFs, "rootfs", "old.txt")) {
		logger.Panic().Msg("old.txt should not exist")
	}

	// Check that .wh.old.txt whiteout file not exists
	whiteoutFile := filepath.Join(dirTempRootFs, "rootfs", ".wh.old.txt")
	if goutils.FileExists(whiteoutFile) {
		logger.Panic().Msg(".wh.old.txt whiteout file should not exist")
	}

    // Inspect the pushed target image manifest using skopeo --raw
    inspectCmd := exec.CommandContext(ctx, "skopeo", "inspect", "--raw", "docker://"+targetImage)
    inspectOutput, err := inspectCmd.CombinedOutput()
    if err != nil {
        logger.Error().Err(err).Str("output", string(inspectOutput)).Msg("Failed to inspect target image manifest")
        return fmt.Errorf("failed to inspect target image: %w", err)
    }

    // Parse raw manifest to check mediaType and layers
    var raw map[string]any
    if err := json.Unmarshal(bytes.TrimSpace(inspectOutput), &raw); err != nil {
        logger.Error().Err(err).Msg("Failed to parse skopeo inspect --raw output")
        return fmt.Errorf("failed to parse inspect output: %w", err)
    }
    mediaType, _ := raw["mediaType"].(string)
    if mediaType == "" {
        logger.Error().Msg("Manifest mediaType is empty in inspected image")
        return fmt.Errorf("manifest mediaType missing")
    }
    logger.Info().Str("mediaType", mediaType).Msg("Inspected target image manifest mediaType")
    return nil
}

// firstNonEmpty returns the first non-empty string from inputs
func firstNonEmpty(values ...string) string {
    for _, v := range values {
        if strings.TrimSpace(v) != "" {
            return v
        }
    }
    return ""
}
