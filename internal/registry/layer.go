package registry

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// UploadLayerToRegistryWithAuth uploads layer to registry with authentication
func UploadLayerToRegistryWithAuth(reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
	// Ensure registryURL does not end with /
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}

	// Try to use Bearer token authentication
	if username != "" && password != "" {
		log.Info().Str("registryURL", registryURL).Str("repository", repository).Str("username", username).Msg("Attempting to upload layer with username/password")

		// First try POST request to see if authentication is required
		postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
		req, err := http.NewRequest("POST", postURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create POST request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("POST request failed: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			if strings.HasPrefix(wwwAuth, "Bearer") {
				// Use Bearer token authentication
				token, err := getTokenFromWWWAuth(wwwAuth, username, password)
				if err != nil {
					log.Error().Err(err).Msg("Failed to get token")
					return fmt.Errorf("failed to get token: %w", err)
				}
				return uploadLayerWithToken(client, reader, sha256sum, registryURL, repository, token)
			} else {
				// Use basic authentication
				return uploadLayerWithBasicAuth(client, reader, sha256sum, registryURL, repository, username, password)
			}
		} else if resp.StatusCode == http.StatusAccepted {
			// No authentication required, upload directly
			location := resp.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("failed to get Location header")
			}
			return continueUpload(client, reader, sha256sum, registryURL, repository, location)
		} else {
			return fmt.Errorf("POST request returned unexpected status code: %d", resp.StatusCode)
		}
	}

	return fmt.Errorf("authentication information required")
}

// uploadLayerWithToken uploads layer using token authentication
func uploadLayerWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, token string) error {
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

	return continueUploadWithToken(client, reader, sha256sum, registryURL, repository, location, token)
}

// continueUploadWithToken continues upload using token authentication
func continueUploadWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string, token string) error {
	// If location is relative path, convert to absolute path
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// Add digest parameter
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("Uploading layer data")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
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

	log.Info().Msg("Layer upload successful")
	return nil
}

// uploadLayerWithBasicAuth uploads layer using basic authentication
func uploadLayerWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
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

	return continueUpload(client, reader, sha256sum, registryURL, repository, location)
}

// continueUpload continues upload without authentication
func continueUpload(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string) error {
	// If location is relative path, convert to absolute path
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// Add digest parameter
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("Uploading layer data")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("Layer upload successful")
	return nil
}

// continueUploadWithBasicAuth continues upload using basic authentication
func continueUploadWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location, username, password string) error {
	// If location is relative path, convert to absolute path
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// Add digest parameter
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("Uploading layer data")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
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

	log.Info().Msg("Layer upload successful")
	return nil
}