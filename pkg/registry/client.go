package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Token authentication token
type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	IssuedAt    time.Time `json:"issued_at"`
}

// Client registry client
type Client struct {
	registryURL string
	username    string
	password    string
	httpClient  *http.Client
	tokenCache  map[string]*Token
	tokenMutex  sync.RWMutex
}

// IsExpired checks if token is expired
// Parameters:
// - ctx: context for the operation
// Returns:
// - bool: true if token is expired, false otherwise
func (t *Token) IsExpired(ctx context.Context) bool {
	logger := log.Ctx(ctx)

	// Handle tokens with expires_in=0 - treat them as long-lived (1 hour default)
	expiresIn := t.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // Default to 1 hour for tokens without explicit expiry
		logger.Debug().
			Int("original_expires_in", t.ExpiresIn).
			Int("effective_expires_in", expiresIn).
			Msg("Token has no explicit expiry, using default duration")
	}

	// Add 60 second buffer before actual expiry to avoid race conditions
	bufferTime := 60 * time.Second
	expiryTime := t.IssuedAt.Add(time.Duration(expiresIn)*time.Second - bufferTime)
	isExpired := time.Now().After(expiryTime)

	logger.Debug().
		Time("issued_at", t.IssuedAt).
		Int("original_expires_in", t.ExpiresIn).
		Int("effective_expires_in", expiresIn).
		Time("expiry_time", expiryTime).
		Bool("is_expired", isExpired).
		Str("phase", "auth").
		Msg("Token expiry check")

	return isExpired
}

// NewClient creates a new registry client
// Parameters:
// - registryURL: URL of the registry
// - username: username for authentication
// - password: password for authentication
// Returns:
// - *Client: pointer to the newly created client
func NewClient(registryURL, username, password string) *Client {
	return &Client{
		registryURL: registryURL,
		username:    username,
		password:    password,
		httpClient: &http.Client{
			Timeout: 60 * time.Minute, // Add timeout to prevent hanging requests
		},
		tokenCache: make(map[string]*Token),
	}
}

// getAuthorizationHeader gets authorization header
// Parameters:
// - ctx: context for the operation
// - scope: scope for which to get authorization
// Returns:
// - string: authorization header value
// - error: any error that occurred while getting the authorization header
func (c *Client) getAuthorizationHeader(ctx context.Context, scope string) (string, error) {
	logger := log.Ctx(ctx)

	c.tokenMutex.RLock()
	token, exists := c.tokenCache[scope]
	c.tokenMutex.RUnlock()

	logger.Debug().
		Str("scope", scope).
		Bool("token_exists", exists).
		Str("phase", "auth").
		Msg("Checking token cache")

	if !exists || token.IsExpired(ctx) {
		logger.Info().
			Str("scope", scope).
			Bool("existed", exists).
			Bool("expired", exists && token.IsExpired(ctx)).
			Str("phase", "auth").
			Msg("Fetching new token")

		var err error
		token, err = c.fetchToken(ctx, scope)
		if err != nil {
			logger.Error().Err(err).Str("scope", scope).Str("phase", "auth").Msg("Failed to fetch token")
			return "", err
		}

		c.tokenMutex.Lock()
		c.tokenCache[scope] = token
		c.tokenMutex.Unlock()

		logger.Info().Str("scope", scope).Str("phase", "auth").Msg("Token cached successfully")
	} else {
		logger.Debug().Str("scope", scope).Str("phase", "auth").Msg("Using cached token")
	}

	return "Bearer " + token.AccessToken, nil
}

// InvalidateToken removes a token from cache (useful when receiving 401 errors)
// Parameters:
// - ctx: context for the operation
// - scope: scope of the token to invalidate
func (c *Client) InvalidateToken(ctx context.Context, scope string) {
	logger := log.Ctx(ctx)

	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	if _, exists := c.tokenCache[scope]; exists {
		logger.Info().Str("scope", scope).Str("phase", "auth").Msg("Invalidating cached token due to authentication failure")
		delete(c.tokenCache, scope)
	}
}

// fetchToken fetches authentication token
// Parameters:
// - ctx: context for the operation
// - scope: scope for which to fetch token
// Returns:
// - *Token: pointer to the fetched token
// - error: any error that occurred while fetching the token
func (c *Client) fetchToken(ctx context.Context, scope string) (*Token, error) {
	logger := log.Ctx(ctx)

	logger.Debug().Str("scope", scope).Str("phase", "auth").Int("step", 0).Msg("Starting token fetch")

	authURL, err := c.getAuthURL(ctx, scope)
	if err != nil {
		logger.Error().Err(err).Str("phase", "auth").Int("step", 0).Msg("Failed to get auth URL")
		return nil, err
	}

	logger.Debug().Str("auth_url", authURL).
		Str("username", c.username).
		Str("password", c.password).
		Str("phase", "auth").Int("step", 1).Msg("Requesting token from auth server")

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}

	// Only set Basic auth when both username and password are provided
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Error().Err(err).Str("auth_url", authURL).Str("phase", "auth").Int("step", 1).Msg("HTTP request to auth server failed")
		return nil, fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error().
			Int("status_code", resp.StatusCode).
			Str("response_body", string(body)).
			Str("auth_url", authURL).
			Str("phase", "auth").
			Int("step", 1).
			Msg("Authentication failed")
		return nil, fmt.Errorf("authentication failed: %s, response: %s", resp.Status, string(body))
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		logger.Error().Err(err).Str("phase", "auth").Int("step", 2).Msg("Failed to decode token response")
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	token.IssuedAt = time.Now()

	logger.Info().
		Str("scope", scope).
		Time("issued_at", token.IssuedAt).
		Int("expires_in", token.ExpiresIn).
		Str("phase", "auth").
		Int("step", 3).
		Msg("Token fetched successfully")

	return &token, nil
}

// getAuthURL gets authentication URL
// Parameters:
// - ctx: context for the operation
// - scope: scope for which to get auth URL
// Returns:
// - string: authentication URL
// - error: any error that occurred while getting the auth URL
func (c *Client) getAuthURL(ctx context.Context, scope string) (string, error) {
	// 尝试访问一个需要认证的端点来获取 WWW-Authenticate 头
	testURL := c.registryURL + "/v2/"
	resp, err := c.httpClient.Get(testURL)
	if err != nil {
		return "", fmt.Errorf("failed to get auth info: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected status code 401, got: %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("WWW-Authenticate header not found")
	}

	// 解析 WWW-Authenticate 头
	// 格式: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("unsupported auth type")
	}

	params := strings.Split(wwwAuth[7:], ",")
	var realm, service string

	for _, param := range params {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "realm=") {
			realm = strings.Trim(param[6:], "\"")
		} else if strings.HasPrefix(param, "service=") {
			service = strings.Trim(param[8:], "\"")
		}
	}

	if realm == "" || service == "" {
		return "", fmt.Errorf("missing required auth parameters")
	}

	// 构建认证 URL
	authURL := fmt.Sprintf("%s?service=%s", realm, url.QueryEscape(service))
	if scope != "" {
		authURL += "&scope=" + url.QueryEscape(scope)
	}

	return authURL, nil
}

// UploadManifest uploads image manifest
// Parameters:
// - ctx: context for the operation
// - repository: repository to upload to
// - reference: reference (tag or digest) for the manifest
// - manifest: manifest data to upload
// - contentType: content type of the manifest
// Returns:
// - error: any error that occurred during manifest upload
func (c *Client) UploadManifest(ctx context.Context, repository, reference string, manifest []byte, contentType string) error {
	logger := log.Ctx(ctx)
	logger.Info().
		Str("repository", repository).
		Str("reference", reference).
		Str("manifest", string(manifest)).
		Msg("UploadManifest")

	endpoint := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	req, err := http.NewRequestWithContext(ctx, "PUT", c.registryURL+endpoint, strings.NewReader(string(manifest)))
	if err != nil {
		return fmt.Errorf("failed to create upload manifest request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetry(ctx, "manifest-upload", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		return c.httpClient.Do(req)
	})
	if err != nil {
		return fmt.Errorf("failed to upload manifest after retries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		// If we get 401, invalidate the token
		if resp.StatusCode == http.StatusUnauthorized {
			c.InvalidateToken(ctx, scope)
		}
		return fmt.Errorf("failed to upload manifest, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetManifest retrieves an image manifest using the centralized client and token cache
// Parameters:
// - ctx: context for the operation
// - repository: repository to fetch from
// - reference: tag or digest reference
// Returns manifest bytes, content type, and error if any
func (c *Client) GetManifest(ctx context.Context, repository, reference string) ([]byte, string, error) {
	endpoint := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	// Read-only operation should request pull scope only
	scope := fmt.Sprintf("repository:%s:pull", repository)

	req, err := http.NewRequestWithContext(ctx, "GET", c.registryURL+endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create manifest request: %w", err)
	}

	// Accept both Docker and OCI manifest formats
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetry(ctx, "manifest-get", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		return c.httpClient.Do(req)
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get manifest after retries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// If we get 401, invalidate the token
		if resp.StatusCode == http.StatusUnauthorized {
			c.InvalidateToken(ctx, scope)
		}
		return nil, "", fmt.Errorf("failed to get manifest, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read manifest body: %w", err)
	}
	contentType := resp.Header.Get("Content-Type")
	return body, contentType, nil
}

// GetBlob retrieves a blob (e.g., config) using the centralized client and token cache
// Parameters:
// - ctx: context for the operation
// - repository: repository name
// - digest: blob digest like sha256:...
// Returns blob bytes and error if any
func (c *Client) GetBlob(ctx context.Context, repository, digest string) ([]byte, error) {
	endpoint := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	// Read-only operation should request pull scope only
	scope := fmt.Sprintf("repository:%s:pull", repository)

	req, err := http.NewRequestWithContext(ctx, "GET", c.registryURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob request: %w", err)
	}

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetry(ctx, "blob-get", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		return c.httpClient.Do(req)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get blob after retries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// If we get 401, invalidate token
		if resp.StatusCode == http.StatusUnauthorized {
			c.InvalidateToken(ctx, scope)
		}
		return nil, fmt.Errorf("failed to get blob, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob body: %w", err)
	}
	return body, nil
}

// BlobExists checks if a blob exists in the target repository using a HEAD request
// Parameters:
// - ctx: context for the operation
// - repository: repository name
// - digest: blob digest like sha256:...
// Returns true if exists, false if 404, or error for other cases
func (c *Client) BlobExists(ctx context.Context, repository, digest string) (bool, error) {
	endpoint := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	scope := fmt.Sprintf("repository:%s:pull", repository)

	req, err := http.NewRequestWithContext(ctx, "HEAD", c.registryURL+endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create blob HEAD request: %w", err)
	}

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return false, fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetryAndTokenInvalidator(ctx, "blob-head", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		return c.httpClient.Do(req)
	}, func() {
		c.InvalidateToken(ctx, scope)
	})
	if err != nil {
		return false, fmt.Errorf("failed to head blob after retries: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusUnauthorized:
		c.InvalidateToken(ctx, scope)
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unauthorized when checking blob: %s", string(body))
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status on blob HEAD: %d, response: %s", resp.StatusCode, string(body))
	}
}

// GetBlobStream retrieves a blob as a streaming reader. Caller must Close the reader.
// Parameters:
// - ctx: context for the operation
// - repository: repository name
// - digest: blob digest like sha256:...
// Returns an io.ReadCloser for streaming the blob content
func (c *Client) GetBlobStream(ctx context.Context, repository, digest string) (io.ReadCloser, error) {
	logger := log.Ctx(ctx)
	logger.Info().
		Str("repository", repository).
		Str("digest", digest).
		Msg("GetBlobStream")

	endpoint := fmt.Sprintf("/v2/%s/blobs/%s", repository, digest)
	scope := fmt.Sprintf("repository:%s:pull", repository)

	req, err := http.NewRequestWithContext(ctx, "GET", c.registryURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob GET request: %w", err)
	}

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	retryConfig := DefaultRetryConfig()
	resp, err := WithRetryAndTokenInvalidator(ctx, "blob-get-stream", retryConfig, func() (*http.Response, error) {
		// Refresh auth header for each attempt
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
		logger.Info().
			Str("repository", repository).
			Str("digest", digest).
			Str("authHeader", authHeader).
			Msg("GetBlobStream")
		return c.httpClient.Do(req)
	}, func() {
		c.InvalidateToken(ctx, scope)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get blob stream after retries: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			c.InvalidateToken(ctx, scope)
		}
		return nil, fmt.Errorf("failed to get blob stream, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	// Caller must Close()
	return resp.Body, nil
}
