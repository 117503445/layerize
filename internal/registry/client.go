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
func (t *Token) IsExpired() bool {
	// Handle tokens with expires_in=0 - treat them as long-lived (1 hour default)
	expiresIn := t.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // Default to 1 hour for tokens without explicit expiry
		log.Debug().
			Int("original_expires_in", t.ExpiresIn).
			Int("effective_expires_in", expiresIn).
			Msg("Token has no explicit expiry, using default duration")
	}
	
	// Add 60 second buffer before actual expiry to avoid race conditions
	bufferTime := 60 * time.Second
	expiryTime := t.IssuedAt.Add(time.Duration(expiresIn)*time.Second - bufferTime)
	isExpired := time.Now().After(expiryTime)
	
	log.Debug().
		Time("issued_at", t.IssuedAt).
		Int("original_expires_in", t.ExpiresIn).
		Int("effective_expires_in", expiresIn).
		Time("expiry_time", expiryTime).
		Bool("is_expired", isExpired).
		Msg("Token expiry check")
	
	return isExpired
}

// NewClient creates a new registry client
func NewClient(registryURL, username, password string) *Client {
	return &Client{
		registryURL: registryURL,
		username:    username,
		password:    password,
		httpClient:  &http.Client{
			Timeout: 60 * time.Second, // Add timeout to prevent hanging requests
		},
		tokenCache:  make(map[string]*Token),
	}
}

// getAuthorizationHeader gets authorization header
func (c *Client) getAuthorizationHeader(ctx context.Context, scope string) (string, error) {
	c.tokenMutex.RLock()
	token, exists := c.tokenCache[scope]
	c.tokenMutex.RUnlock()

	log.Debug().
		Str("scope", scope).
		Bool("token_exists", exists).
		Msg("Checking token cache")

	if !exists || token.IsExpired() {
		log.Info().
			Str("scope", scope).
			Bool("existed", exists).
			Bool("expired", exists && token.IsExpired()).
			Msg("Fetching new token")
		
		var err error
		token, err = c.fetchToken(ctx, scope)
		if err != nil {
			log.Error().Err(err).Str("scope", scope).Msg("Failed to fetch token")
			return "", err
		}

		c.tokenMutex.Lock()
		c.tokenCache[scope] = token
		c.tokenMutex.Unlock()
		
		log.Info().Str("scope", scope).Msg("Token cached successfully")
	} else {
		log.Debug().Str("scope", scope).Msg("Using cached token")
	}

	return "Bearer " + token.AccessToken, nil
}

// InvalidateToken removes a token from cache (useful when receiving 401 errors)
func (c *Client) InvalidateToken(scope string) {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()
	
	if _, exists := c.tokenCache[scope]; exists {
		log.Info().Str("scope", scope).Msg("Invalidating cached token due to authentication failure")
		delete(c.tokenCache, scope)
	}
}

// fetchToken fetches authentication token
func (c *Client) fetchToken(ctx context.Context, scope string) (*Token, error) {
	log.Debug().Str("scope", scope).Msg("Starting token fetch")
	
	authURL, err := c.getAuthURL(ctx, scope)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get auth URL")
		return nil, err
	}

	log.Debug().Str("auth_url", authURL).Msg("Requesting token from auth server")
	
	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Error().Err(err).Str("auth_url", authURL).Msg("HTTP request to auth server failed")
		return nil, fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error().
			Int("status_code", resp.StatusCode).
			Str("response_body", string(body)).
			Str("auth_url", authURL).
			Msg("Authentication failed")
		return nil, fmt.Errorf("authentication failed: %s, response: %s", resp.Status, string(body))
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		log.Error().Err(err).Msg("Failed to decode token response")
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	token.IssuedAt = time.Now()
	
	log.Info().
		Str("scope", scope).
		Time("issued_at", token.IssuedAt).
		Int("expires_in", token.ExpiresIn).
		Msg("Token fetched successfully")
	
	return &token, nil
}

// getAuthURL gets authentication URL
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
func (c *Client) UploadManifest(ctx context.Context, repository, reference string, manifest []byte, contentType string) error {
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
			c.InvalidateToken(scope)
		}
		return fmt.Errorf("failed to upload manifest, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}
