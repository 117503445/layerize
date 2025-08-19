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

// Token 认证令牌
type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	IssuedAt    time.Time `json:"issued_at"`
}

// Client registry 客户端
type Client struct {
	registryURL string
	username    string
	password    string
	httpClient  *http.Client
	tokenCache  map[string]*Token
	tokenMutex  sync.RWMutex
}

// IsExpired 检查令牌是否过期
func (t *Token) IsExpired() bool {
	return time.Now().After(t.IssuedAt.Add(time.Duration(t.ExpiresIn-60) * time.Second))
}

// NewClient 创建新的 registry 客户端
func NewClient(registryURL, username, password string) *Client {
	return &Client{
		registryURL: registryURL,
		username:    username,
		password:    password,
		httpClient:  &http.Client{},
		tokenCache:  make(map[string]*Token),
	}
}

// getAuthorizationHeader 获取授权头
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

// fetchToken 获取认证令牌
func (c *Client) fetchToken(ctx context.Context, scope string) (*Token, error) {
	authURL, err := c.getAuthURL(ctx, scope)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建认证请求失败: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("认证请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("认证失败: %s, 响应: %s", resp.Status, string(body))
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("解析令牌失败: %w", err)
	}

	token.IssuedAt = time.Now()
	return &token, nil
}

// doRequest 执行 HTTP 请求
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body io.Reader, scope string) (*http.Response, error) {
	url := c.registryURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	if scope != "" {
		authHeader, err := c.getAuthorizationHeader(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("获取授权头失败: %w", err)
		}
		req.Header.Set("Authorization", authHeader)
	}

	return c.httpClient.Do(req)
}

// parseScopeFromWWWAuth 从 WWW-Authenticate 头解析 scope
func parseScopeFromWWWAuth(wwwAuth string) (string, error) {
	// 解析形如: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("不支持的认证类型: %s", wwwAuth)
	}

	params := strings.Split(wwwAuth[7:], ",")
	for _, param := range params {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "scope=") {
			scope := strings.Trim(param[6:], "\"")
			return scope, nil
		}
	}

	return "", fmt.Errorf("未找到 scope 参数")
}

// getAuthURL 获取认证 URL
func (c *Client) getAuthURL(ctx context.Context, scope string) (string, error) {
	// 尝试访问一个需要认证的端点来获取 WWW-Authenticate 头
	testURL := c.registryURL + "/v2/"
	resp, err := c.httpClient.Get(testURL)
	if err != nil {
		return "", fmt.Errorf("获取认证信息失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("期望状态码 401，实际获得: %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("未找到 WWW-Authenticate 头")
	}

	// 解析 WWW-Authenticate 头
	// 格式: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("不支持的认证类型")
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
		return "", fmt.Errorf("缺少必要的认证参数")
	}

	// 构建认证 URL
	authURL := fmt.Sprintf("%s?service=%s", realm, url.QueryEscape(service))
	if scope != "" {
		authURL += "&scope=" + url.QueryEscape(scope)
	}

	return authURL, nil
}

// uploadLayer 上传层
func (c *Client) uploadLayer(ctx context.Context, repository, digest string, layerData io.Reader) error {
	// 开始上传
	initURL := fmt.Sprintf("/v2/%s/blobs/uploads/", repository)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	resp, err := c.doRequest(ctx, "POST", initURL, nil, scope)
	if err != nil {
		return fmt.Errorf("初始化上传失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("初始化上传失败，状态码: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("未获取到上传位置")
	}

	// 如果 location 是相对路径，转换为绝对路径
	if strings.HasPrefix(location, "/") {
		location = c.registryURL + location
	}

	// 上传数据
	uploadURL := location + "&digest=sha256:" + digest
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, layerData)
	if err != nil {
		return fmt.Errorf("创建上传请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("获取授权头失败: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("上传请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getManifest 获取镜像清单
func (c *Client) getManifest(ctx context.Context, repository, reference string) ([]byte, string, error) {
	endpoint := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	scope := fmt.Sprintf("repository:%s:pull", repository)

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, scope)
	if err != nil {
		return nil, "", fmt.Errorf("获取清单失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取清单失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取清单内容失败: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	return body, contentType, nil
}

// UploadManifest 上传镜像清单
func (c *Client) UploadManifest(ctx context.Context, repository, reference string, manifest []byte, contentType string) error {
	endpoint := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	req, err := http.NewRequestWithContext(ctx, "PUT", c.registryURL+endpoint, strings.NewReader(string(manifest)))
	if err != nil {
		return fmt.Errorf("创建上传清单请求失败: %w", err)
	}

	req.Header.Set("Content-Type", contentType)

	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("获取授权头失败: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("上传清单失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传清单失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	return nil
}