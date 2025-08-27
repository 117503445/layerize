package main

import (
	"context"
	"os"
	"testing"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/pkg/builder"
	"github.com/117503445/layerize/pkg/types"
	"github.com/117503445/layerize/pkg/validator"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	goutils.InitZeroLog()
	os.Exit(m.Run())
}

func TestBuildAndValidateImage(t *testing.T) {
	fileEnv := ".env"

	// Skip test if .env file is not present
	if _, err := os.Stat(fileEnv); os.IsNotExist(err) {
		t.Skip(".env file not found, skipping integration test")
	}

	ctx := context.Background()
	ctx = log.Logger.WithContext(ctx)

	logger := log.Ctx(ctx)

	logger.Info().
		Str("phase", "init").
		Int("step", 0).
		Msg("Starting Layerize test")

	// Load .env file
	err := godotenv.Load(fileEnv)
	require.NoError(t, err, "Failed to load .env file")
	logger.Info().Str("phase", "init").Int("step", 1).Msg("Loaded .env environment variables")

	baseImage := os.Getenv("base_image")
	targetImage := os.Getenv("target_image")

	// Check if required environment variables are set
	if baseImage == "" || targetImage == "" {
		t.Skip("base_image or target_image not set, skipping integration test")
	}

	// Optional: separate credentials for base and target
	baseUsername := os.Getenv("base_username")
	basePassword := os.Getenv("base_password")
	targetUsername := os.Getenv("target_username")
	targetPassword := os.Getenv("target_password")

	targetAuth := types.Auth{Username: targetUsername, Password: targetPassword}
	baseAuth := types.Auth{Username: baseUsername, Password: basePassword}

	content := goutils.TimeStrMilliSec()

	// Create file mapping to simulate content in tmp/diff.tar
	files := map[string][]byte{
		"new.txt":     []byte(content),
		".wh.old.txt": []byte(""),
	}
	logger.Info().
		Str("phase", "build").
		Int("step", 0).
		Str("target_image", targetImage).
		Str("base_image", baseImage).
		Msg("Ready to start image building")

	// Call buildImageFromMap function to execute build operation
	err = builder.BuildImageFromMap(
		ctx,
		files,
		targetImage, // target image (with tag)
		targetAuth,  // target auth
		baseImage,   // base image (with tag)
		baseAuth,    // base image auth
	)
	require.NoError(t, err, "buildImageFromMap execution failed")

	// Validate the built image
	err = validator.ValidateBuiltImage(ctx, targetImage, content)
	assert.NoError(t, err, "Image validation failed")
}

// TestSyncBlobs tests the blob synchronization functionality
func TestSyncBlobs(t *testing.T) {
	fileEnv := ".env"

	// Skip test if .env file is not present
	if _, err := os.Stat(fileEnv); os.IsNotExist(err) {
		t.Skip(".env file not found, skipping integration test")
	}

	ctx := context.Background()
	ctx = log.Logger.WithContext(ctx)

	logger := log.Ctx(ctx)

	logger.Info().
		Str("phase", "init").
		Int("step", 0).
		Msg("Starting SyncBlobs test")

	// Load .env file
	err := godotenv.Load(fileEnv)
	require.NoError(t, err, "Failed to load .env file")
	logger.Info().Str("phase", "init").Int("step", 1).Msg("Loaded .env environment variables")

	baseImage := os.Getenv("base_image")
	targetImage := os.Getenv("target_image")

	// Check if required environment variables are set
	if baseImage == "" || targetImage == "" {
		t.Skip("base_image or target_image not set, skipping integration test")
	}

	// Optional: separate credentials for base and target
	baseUsername := os.Getenv("base_username")
	basePassword := os.Getenv("base_password")
	targetUsername := os.Getenv("target_username")
	targetPassword := os.Getenv("target_password")

	syncParams := types.SyncBlobsParams{
		BaseImage: baseImage,
		BaseImageAuth: types.Auth{
			Username: baseUsername,
			Password: basePassword,
		},
		TargetImage: targetImage,
		TargetAuth: types.Auth{
			Username: targetUsername,
			Password: targetPassword,
		},
	}

	// Call SyncBlobs function to execute blob synchronization
	err = builder.SyncBlobs(ctx, syncParams)
	require.NoError(t, err, "SyncBlobs execution failed")

	logger.Info().Msg("SyncBlobs test completed successfully")
}