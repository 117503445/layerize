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

    // Read common authentication information from environment variables
    commonUsername := os.Getenv("username")
    commonPassword := os.Getenv("password")
    commonAuth := types.Auth{Username: commonUsername, Password: commonPassword}

    // Optional: separate credentials for base and target
    baseUsername := os.Getenv("base_username")
    basePassword := os.Getenv("base_password")
    targetUsername := os.Getenv("target_username")
    targetPassword := os.Getenv("target_password")

    // Target auth falls back to common creds
    targetAuth := commonAuth
    if targetUsername != "" || targetPassword != "" {
        targetAuth = types.Auth{Username: targetUsername, Password: targetPassword}
    }

    // Base auth falls back to common creds (never to target creds)
    baseAuth := commonAuth
    if baseUsername != "" || basePassword != "" {
        baseAuth = types.Auth{Username: baseUsername, Password: basePassword}
    }
	content := goutils.TimeStrMilliSec()

    // Create file mapping to simulate content in tmp/diff.tar
	files := map[string][]byte{
		"new.txt":     []byte(content),
		".wh.old.txt": []byte(""),
	}
    logger.Info().
        Str("phase", "build").
        Int("step", 0).
        Str("target_image", "registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357").
        Str("base_image", "registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:latest").
        Msg("Ready to start image building")
	for i := range 1 {
        logger.Info().Str("phase", "build").Int("step", 1).Int("test_case", i).Msg("Start executing image build and validation")

        // Call buildImageFromMap function to execute build operation
        err = builder.BuildImageFromMap(
            ctx,
            files,
            "registry.cn-hangzhou.aliyuncs.com/devs_test/devpod-e2e-test:20250825.033411.512", // target image (with tag)
            targetAuth,                                // target auth
            "serverless-registry.cn-hangzhou.cr.aliyuncs.com/functionai/python:3.13",    // base image (with tag)
            baseAuth,                                  // base image auth
        )
		if err != nil {
			logger.Error().Err(err).Msg("buildImageFromMap execution failed")
			panic(err)
		}

        logger.Info().Str("phase", "build").Int("step", 2).Int("test_case", i).Msg("Image building completed")

		// Validate the built image
		err = validator.ValidateBuiltImage(ctx, content)
		if err != nil {
			logger.Error().Err(err).Msg("Image validation failed")
			panic(err)
		}

        logger.Info().Str("phase", "validate").Int("step", 3).Int("test_case", i).Msg("Image validation completed")
	}
}