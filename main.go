package main

import (
	"context"
	"os"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/pkg/builder"
	"github.com/117503445/layerize/pkg/types"
	"github.com/117503445/layerize/pkg/validator"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	goutils.InitZeroLog()

	ctx := context.Background()
	ctx = log.Logger.WithContext(ctx)

	logger := log.Ctx(ctx)

	logger.Info().
		Str("phase", "init").
		Int("step", 0).
		Msg("Starting Layerize sample program")

	// Load .env file
	err := godotenv.Load()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load .env file")
		panic(err)
	}
	logger.Info().Str("phase", "init").Int("step", 1).Msg("Loaded .env environment variables")

	baseImage := os.Getenv("base_image")
	targetImage := os.Getenv("target_image")

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
	for i := range 1 {
		logger.Info().Str("phase", "build").Int("step", 1).Int("test_case", i).Msg("Start executing image build and validation")

		// Call buildImageFromMap function to execute build operation
		err = builder.BuildImageFromMap(
			ctx,
			files,
			targetImage, // target image (with tag)
			targetAuth,  // target auth
			baseImage,   // base image (with tag)
			baseAuth,    // base image auth
		)
		if err != nil {
			logger.Error().Err(err).Msg("buildImageFromMap execution failed")
			panic(err)
		}

		logger.Info().Str("phase", "build").Int("step", 2).Int("test_case", i).Msg("Image building completed")

		// Validate the built image
		err = validator.ValidateBuiltImage(ctx, targetImage, content)
		if err != nil {
			logger.Error().Err(err).Msg("Image validation failed")
			panic(err)
		}

		logger.Info().Str("phase", "validate").Int("step", 3).Int("test_case", i).Msg("Image validation completed")
	}
}
