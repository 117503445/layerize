package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetManifestWithAuth retrieves image manifest with authentication
func GetManifestWithAuth(ctx context.Context, registryURL, repository, reference, username, password string) ([]byte, string, error) {
	// Ensure registryURL does not end with /
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, reference)

	// Try without authentication first
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set Accept header to get correct manifest format
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		contentType := resp.Header.Get("Content-Type")
		return body, contentType, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(wwwAuth, "Bearer") && username != "" && password != "" {
			// Use Bearer token authentication
			token, err := getTokenFromWWWAuth(ctx, wwwAuth, username, password)
			if err != nil {
				return nil, "", fmt.Errorf("failed to get token: %w", err)
			}
			return getManifestWithToken(ctx, client, manifestURL, token)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return nil, "", fmt.Errorf("failed to get manifest, status code: %d, response: %s", resp.StatusCode, string(body))
}

// getManifestWithToken retrieves manifest using token authentication
func getManifestWithToken(ctx context.Context, client *http.Client, manifestURL, token string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("failed to get manifest, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	return body, contentType, err
}