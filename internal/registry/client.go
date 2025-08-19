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
	return time.Now().After(t.IssuedAt.Add(time.Duration(t.ExpiresIn-60) * time.Second))
}

// NewClient creates a new registry client
func NewClient(registryURL, username, password string) *Client {
	return &Client{
		registryURL: registryURL,
		username:    username,
		password:    password,
		httpClient:  &http.Client{},
		tokenCache:  make(map[string]*Token),
	}
}

// getAuthorizationHeader gets authorization header
func (c *Client) getAuthorizationHeader(ctx context.Context, scope string) (string, error) {
	c.tokenMutex.RLock()
	token, exists := c.tokenCache[scope]
	c.tokenMutex.RUnlock()

	if !exists || token.IsExpired() {
		var err error
		token, err = c.fetchToken(ctx, scope)
		if err != nil {
			return "", err
		}

		c.tokenMutex.Lock()
		c.tokenCache[scope] = token
		c.tokenMutex.Unlock()
	}

	return "Bearer " + token.AccessToken, nil
}

// fetchToken fetches authentication token
func (c *Client) fetchToken(ctx context.Context, scope string) (*Token, error) {
	authURL, err := c.getAuthURL(ctx, scope)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed: %s, response: %s", resp.Status, string(body))
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	token.IssuedAt = time.Now()
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to upload manifest, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}
