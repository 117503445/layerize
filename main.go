package main

import (
	"context"
	"os"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/internal/builder"
	"github.com/117503445/layerize/internal/types"
	"github.com/117503445/layerize/internal/validator"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	goutils.InitZeroLog()

	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Error().Err(err).Msg("Failed to load .env file")
		panic(err)
	}

	// Read authentication information from environment variables
	username := os.Getenv("username")
	password := os.Getenv("password")
	auth := types.Auth{Username: username, Password: password}

	ctx := context.Background()
	content := goutils.TimeStrMilliSec()

	// Create file mapping to simulate content in tmp/diff.tar
	files := map[string][]byte{
		"new.txt":     []byte(content),
		".wh.old.txt": []byte(""),
	}
	for i := range 10 {
		log.Info().Msgf("Building image TestCase %d", i)

		// Call buildImageFromMap function to execute build operation
		err = builder.BuildImageFromMap(
			ctx,
			files,
			"117503445/layerize-test-base", // target image
			auth,                           // target auth
			"117503445/layerize-test-base", // base image name
			auth,                           // base image auth
			"latest",                       // base image tag
			"08182357",                     // target image tag
		)
		if err != nil {
			log.Error().Err(err).Msg("buildImageFromMap execution failed")
			panic(err)
		}

		log.Info().Msg("Image build completed")

		// Validate the built image
		err = validator.ValidateBuiltImage(ctx, content)
		if err != nil {
			log.Error().Err(err).Msg("Image validation failed")
			panic(err)
		}

		log.Info().Msg("Image validation completed")
	}
}
