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

// doRequest executes HTTP request
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body io.Reader, scope string) (*http.Response, error) {
	url := c.registryURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if scope != "" {
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth header: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
	}

	return c.httpClient.Do(req)
}

// parseScopeFromWWWAuth parses scope from WWW-Authenticate header
func parseScopeFromWWWAuth(wwwAuth string) (string, error) {
	// 解析形如: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("unsupported auth type: %s", wwwAuth)
	}

	params := strings.Split(wwwAuth[7:], ",")
	for _, param := range params {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "scope=") {
			scope := strings.Trim(param[6:], "\"")
			return scope, nil
		}
	}

	return "", fmt.Errorf("scope parameter not found")
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

// uploadLayer uploads layer
func (c *Client) uploadLayer(ctx context.Context, repository, digest string, layerData io.Reader) error {
	// Start upload
	initURL := fmt.Sprintf("/v2/%s/blobs/uploads/", repository)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	resp, err := c.doRequest(ctx, "POST", initURL, nil, scope)
	if err != nil {
		return fmt.Errorf("failed to initialize upload: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to initialize upload, status code: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("failed to get upload location")
	}

	// Convert relative path to absolute path if needed
	if strings.HasPrefix(location, "/") {
		location = c.registryURL + location
	}

	// Upload data
	uploadURL := location + "&digest=sha256:" + digest
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, layerData)
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to get auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("上传请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getManifest gets image manifest
func (c *Client) getManifest(ctx context.Context, repository, reference string) ([]byte, string, error) {
	endpoint := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	scope := fmt.Sprintf("repository:%s:pull", repository)

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, scope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to get manifest, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read manifest content: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	return body, contentType, nil
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