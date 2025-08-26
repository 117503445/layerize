package registry

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ProgressReader wraps an io.Reader and tracks the number of bytes read
type ProgressReader struct {
	Reader     io.Reader
	BytesRead  int64
	OnProgress func(bytesRead int64)
}

// Read implements the io.Reader interface
func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	pr.BytesRead += int64(n)

	// Call the progress callback if provided
	if pr.OnProgress != nil {
		pr.OnProgress(pr.BytesRead)
	}

	return n, err
}

// UploadLayerWithClient uploads layer using the centralized client with token management
func UploadLayerWithClient(ctx context.Context, client *Client, reader io.Reader, sha256sum, repository string) error {
	logger := log.Ctx(ctx)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	logger.Info().
		Str("repository", repository).
		Str("scope", scope).
		Str("layer_sha256", sha256sum).
		Str("phase", "upload").
		Int("step", 0).
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

	logger.Debug().Str("upload_location", location).Str("phase", "upload").Int("step", 1).Msg("Layer upload initiated successfully")

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

	logger.Debug().Str("final_upload_url", finalUploadURL).Str("phase", "upload").Int("step", 2).Msg("Uploading layer data")

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
		logger.Error().
			Int("status_code", putResp.StatusCode).
			Str("response_body", string(body)).
			Str("upload_url", finalUploadURL).
			Str("phase", "upload").
			Int("step", 2).
			Msg("Layer upload failed")
		// If we get 401, invalidate the token
		if putResp.StatusCode == http.StatusUnauthorized {
			client.InvalidateToken(ctx, scope)
		}
		return fmt.Errorf("layer upload failed, status code: %d, response: %s", putResp.StatusCode, string(body))
	}

	logger.Info().
		Str("repository", repository).
		Str("digest", digest).
		Str("phase", "upload").
		Int("step", 3).
		Msg("Layer upload successful using centralized client")
	return nil
}

// UploadLayerStreamWithClient uploads a layer stream to registry with provided http client
// Parameters:
// - ctx: context for the operation
// - repository: target repository
// - digest: layer digest
// - reader: layer data reader
// Returns:
// - error: error if any
func (client *Client) UploadLayerStreamWithClient(ctx context.Context, repository, digest string, reader io.Reader) error {
	logger := log.Ctx(ctx)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	logger.Info().Str("repository", repository).Str("digest", digest).Str("phase", "upload").Msg("Starting streaming layer upload")

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

	var finalUploadURL string
	if strings.HasPrefix(location, "/") {
		finalUploadURL = client.registryURL + location
	} else {
		finalUploadURL = location
	}

	if strings.Contains(finalUploadURL, "?") {
		finalUploadURL += "&digest=" + digest
	} else {
		finalUploadURL += "?digest=" + digest
	}

	// Wrap the reader with progress tracking
	progressReader := &ProgressReader{
		Reader: reader,
		OnProgress: func(bytesRead int64) {
			// logger.Debug().Int64("bytes_uploaded", bytesRead).Str("repository", repository).Str("digest", digest).Msg("Layer upload progress")
		},
	}

	// Start progress logging goroutine
	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressTicker.C:
				mb := float64(progressReader.BytesRead) / 1024 / 1024
				logger.Info().
					Int64("bytes_uploaded", progressReader.BytesRead).
					Float64("bytes_uploaded_MB", math.Round(mb*100)/100).
					Str("repository", repository).
					Str("digest", digest).
					Msg("Layer upload in progress")
			}
		}
	}()

	// Step 2: Stream the blob
	putReq, err := http.NewRequestWithContext(ctx, "PUT", finalUploadURL, progressReader)
	if err != nil {
		return fmt.Errorf("failed to create layer upload request: %w", err)
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Authorization", authHeader)

	putResp, err := WithRetry(ctx, "layer-upload-put", retryConfig, func() (*http.Response, error) {
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
		logger.Error().Int("status_code", putResp.StatusCode).Str("response_body", string(body)).Str("upload_url", finalUploadURL).Str("phase", "upload").Msg("Streaming layer upload failed")
		if putResp.StatusCode == http.StatusUnauthorized {
			client.InvalidateToken(ctx, scope)
		}
		return fmt.Errorf("layer upload failed, status code: %d, response: %s", putResp.StatusCode, string(body))
	}

	logger.Info().Str("repository", repository).Str("digest", digest).Str("phase", "upload").Msg("Streaming layer upload successful")
	return nil
}
