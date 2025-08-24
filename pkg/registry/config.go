package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// GetConfigWithAuth retrieves image config with authentication
// Parameters:
// - ctx: context for the operation
// - registryURL: URL of the registry
// - repository: repository name
// - reference: reference (tag or digest) of the image
// - username: username for authentication
// - password: password for authentication
// Returns:
// - []byte: image config data
// - error: any error that occurred while retrieving the config
func GetConfigWithAuth(ctx context.Context, registryURL, repository, reference, username, password string) ([]byte, error) {
	// First get the manifest
	manifest, _, err := GetManifestWithAuth(ctx, registryURL, repository, reference, username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	// Parse manifest to get config digest
	var manifestData map[string]any
	if err := json.Unmarshal(manifest, &manifestData); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	config, ok := manifestData["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config field not found in manifest")
	}

	configDigest, ok := config["digest"].(string)
	if !ok {
		return nil, fmt.Errorf("config digest not found in manifest")
	}

	// Ensure registryURL does not end with /
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}
	configURL := fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, repository, configDigest)

	// Try without authentication first
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return io.ReadAll(resp.Body)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(wwwAuth, "Bearer") && username != "" && password != "" {
			// Use Bearer token authentication
			token, err := getTokenFromWWWAuth(ctx, wwwAuth, username, password)
			if err != nil {
				return nil, fmt.Errorf("failed to get token: %w", err)
			}
			return getConfigWithToken(ctx, client, configURL, token)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("failed to get config, status code: %d, response: %s", resp.StatusCode, string(body))
}

// getConfigWithToken retrieves config using token authentication
// Parameters:
// - ctx: context for the operation
// - client: HTTP client to use for the request
// - configURL: URL to retrieve config from
// - token: authentication token
// Returns:
// - []byte: image config data
// - error: any error that occurred while retrieving the config
func getConfigWithToken(ctx context.Context, client *http.Client, configURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get config, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// UploadConfigToRegistryWithAuth uploads config to image registry with authentication
// Parameters:
// - ctx: context for the operation
// - configData: config data to upload
// - configDigest: digest of the config data
// - registryURL: URL of the registry
// - repository: repository name
// - username: username for authentication
// - password: password for authentication
// Returns:
// - error: any error that occurred during config upload
func UploadConfigToRegistryWithAuth(ctx context.Context, configData []byte, configDigest, registryURL, repository, username, password string) error {
	logger := log.Ctx(ctx)

	logger.Info().
		Str("registryURL", registryURL).
		Str("repository", repository).
		Str("username", username).
		Str("configDigest", configDigest).
		Int("configSize", len(configData)).
		Msg("Starting config upload with authentication")

	// Use centralized client for better token management
	client := NewClient(registryURL, username, password)

	// Calculate SHA256 of config data for upload
	hash := sha256.Sum256(configData)
	calculatedDigest := fmt.Sprintf("sha256:%x", hash)

	if configDigest != calculatedDigest {
		logger.Warn().
			Str("provided_digest", configDigest).
			Str("calculated_digest", calculatedDigest).
			Msg("Config digest mismatch - using calculated digest")
		configDigest = calculatedDigest
	}

	return UploadConfigWithClient(ctx, client, configData, configDigest, repository)
}
