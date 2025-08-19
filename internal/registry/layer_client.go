package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// UploadLayerWithClient uploads layer using the centralized client with token management
func UploadLayerWithClient(client *Client, reader io.Reader, sha256sum, repository string) error {
	ctx := context.Background()
	scope := fmt.Sprintf("repository:%s:push,pull", repository)
	
	log.Info().
		Str("repository", repository).
		Str("scope", scope).
		Str("layer_sha256", sha256sum).
		Msg("Starting layer upload with centralized client")

	// Step 1: Initiate blob upload
	uploadURL := fmt.Sprintf("/v2/%s/blobs/uploads/", repository)
	
	req, err := http.NewRequestWithContext(ctx, "POST", client.registryURL+uploadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create upload initiation request: %w", err)
	}

	authHeader, err := client.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetry(ctx, "layer-upload-init", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := client.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		return client.httpClient.Do(req)
	})
	if err != nil {
		return fmt.Errorf("upload initiation request failed after retries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload initiation failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("failed to get Location header from upload initiation")
	}

	log.Debug().Str("upload_location", location).Msg("Layer upload initiated successfully")

	// Step 2: Upload the layer data
	var finalUploadURL string
	if strings.HasPrefix(location, "/") {
		finalUploadURL = client.registryURL + location
	} else {
		finalUploadURL = location
	}

	// Add digest parameter
	digest := "sha256:" + sha256sum
	if strings.Contains(finalUploadURL, "?") {
		finalUploadURL += "&digest=" + digest
	} else {
		finalUploadURL += "?digest=" + digest
	}

	log.Debug().Str("final_upload_url", finalUploadURL).Msg("Uploading layer data")

	putReq, err := http.NewRequestWithContext(ctx, "PUT", finalUploadURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create layer upload request: %w", err)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Authorization", authHeader)

	putResp, err := WithRetry(ctx, "layer-upload-put", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := client.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		putReq.Header.Set("Authorization", authHeader)
		return client.httpClient.Do(putReq)
	})
	if err != nil {
		return fmt.Errorf("layer upload request failed after retries: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
		log.Error().
			Int("status_code", putResp.StatusCode).
			Str("response_body", string(body)).
			Str("upload_url", finalUploadURL).
			Msg("Layer upload failed")
		// If we get 401, invalidate the token
		if putResp.StatusCode == http.StatusUnauthorized {
			client.InvalidateToken(ctx, scope)
		}
		return fmt.Errorf("layer upload failed, status code: %d, response: %s", putResp.StatusCode, string(body))
	}

	log.Info().
		Str("repository", repository).
		Str("digest", digest).
		Msg("Layer upload successful using centralized client")
	return nil
}