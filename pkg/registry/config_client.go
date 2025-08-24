package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// UploadConfigWithClient uploads config using the centralized client with token management
// Parameters:
// - ctx: context for the operation
// - client: registry client to use for upload
// - configData: config data to upload
// - configDigest: digest of the config data
// - repository: repository name
// Returns:
// - error: any error that occurred during config upload
func UploadConfigWithClient(ctx context.Context, client *Client, configData []byte, configDigest, repository string) error {
	logger := log.Ctx(ctx)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)
	
    logger.Info().
		Str("repository", repository).
		Str("scope", scope).
        Str("phase", "upload").
        Int("step", 0).
        Msg("Starting config upload with centralized client")

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
	resp, err := WithRetry(ctx, "config-upload-init", retryConfig, func() (*http.Response, error) {
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

    logger.Debug().Str("upload_location", location).Str("phase", "upload").Int("step", 1).Msg("Upload initiated successfully")

	// Step 2: Upload the config data
	var finalUploadURL string
	if strings.HasPrefix(location, "/") {
		finalUploadURL = client.registryURL + location
	} else {
		finalUploadURL = location
	}

	// Add digest parameter
	if strings.Contains(finalUploadURL, "?") {
		finalUploadURL += "&digest=" + configDigest
	} else {
		finalUploadURL += "?digest=" + configDigest
	}

    logger.Debug().Str("final_upload_url", finalUploadURL).Str("phase", "upload").Int("step", 2).Msg("Uploading config data")

	putReq, err := http.NewRequestWithContext(ctx, "PUT", finalUploadURL, bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("failed to create config upload request: %w", err)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Content-Length", strconv.Itoa(len(configData)))
	putReq.Header.Set("Authorization", authHeader)

	putResp, err := WithRetry(ctx, "config-upload-put", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := client.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		putReq.Header.Set("Authorization", authHeader)
		return client.httpClient.Do(putReq)
	})
	if err != nil {
		return fmt.Errorf("config upload request failed after retries: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
        logger.Error().
			Int("status_code", putResp.StatusCode).
			Str("response_body", string(body)).
			Str("upload_url", finalUploadURL).
            Str("phase", "upload").
            Int("step", 2).
            Msg("Config upload failed")
		// If we get 401, invalidate the token
		if putResp.StatusCode == http.StatusUnauthorized {
			client.InvalidateToken(ctx, scope)
		}
		return fmt.Errorf("config upload failed, status code: %d, response: %s", putResp.StatusCode, string(body))
	}

    logger.Info().
		Str("repository", repository).
		Str("digest", configDigest).
        Str("phase", "upload").
        Int("step", 3).
        Msg("Config upload successful using centralized client")
	return nil
}