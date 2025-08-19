package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// GetConfigWithAuth retrieves image config with authentication
func GetConfigWithAuth(registryURL, repository, reference, username, password string) ([]byte, error) {
	// First get the manifest
	manifest, _, err := GetManifestWithAuth(registryURL, repository, reference, username, password)
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
	req, err := http.NewRequest("GET", configURL, nil)
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
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				return nil, fmt.Errorf("failed to get token: %w", err)
			}
			return getConfigWithToken(client, configURL, token)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("failed to get config, status code: %d, response: %s", resp.StatusCode, string(body))
}

// getConfigWithToken retrieves config using token authentication
func getConfigWithToken(client *http.Client, configURL, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", configURL, nil)
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
func UploadConfigToRegistryWithAuth(configData []byte, configDigest, registryURL, repository, username, password string) error {
	log.Info().
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
		log.Warn().
			Str("provided_digest", configDigest).
			Str("calculated_digest", calculatedDigest).
			Msg("Config digest mismatch - using calculated digest")
		configDigest = calculatedDigest
	}

	return UploadConfigWithClient(client, configData, configDigest, repository)
}

// uploadConfigWithBasicAuth uploads config using basic authentication
func uploadConfigWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, username, password string) error {
	// Start upload
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create POST request: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST request failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST request failed, status code: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("failed to get Location header")
	}

	return continueConfigUploadWithBasicAuth(client, configData, configDigest, registryURL, repository, location, username, password)
}

// uploadConfigWithToken uploads config using token authentication
func uploadConfigWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, token string) error {
	// Start upload
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create POST request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST request failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST request failed, status code: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("failed to get Location header")
	}

	return continueConfigUploadWithToken(client, configData, configDigest, registryURL, repository, location, token)
}

// continueConfigUploadWithBasicAuth continues config upload using basic authentication
func continueConfigUploadWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, location, username, password string) error {
	// If location is relative path, convert to absolute path
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// Add digest parameter
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=" + configDigest
	} else {
		uploadURL += "?digest=" + configDigest
	}

	log.Info().Str("uploadURL", uploadURL).Msg("Uploading config data")

	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(configData)))
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("Config upload successful")
	return nil
}

// continueConfigUploadWithToken continues config upload using token authentication
func continueConfigUploadWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, location, token string) error {
	// If location is relative path, convert to absolute path
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// Add digest parameter
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=" + configDigest
	} else {
		uploadURL += "?digest=" + configDigest
	}

	log.Info().Str("uploadURL", uploadURL).Msg("Uploading config data")

	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(configData)))
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("Config upload successful")
	return nil
}