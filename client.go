package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Client 是一个支持 token 复用的 registry 客户端
type Client struct {
	registryURL string
	username    string
	password    string
	client      *http.Client

	// token 缓存
	tokenCache map[string]*Token
	cacheMutex sync.RWMutex
}

// Token 表示认证 token 信息
type Token struct {
	Token       string    `json:"token"`
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	IssuedAt    time.Time `json:"issued_at"`

	// 内部使用，用于判断是否过期
	expiresAt time.Time
}

// IsExpired 检查 token 是否过期
func (t *Token) IsExpired() bool {
	if t.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.expiresAt)
}

// NewClient 创建一个新的 registry 客户端
func NewClient(registryURL, username, password string) *Client {
	return &Client{
		registryURL: strings.TrimSuffix(registryURL, "/"),
		username:    username,
		password:    password,
		client:      &http.Client{},
		tokenCache:  make(map[string]*Token),
	}
}

// getAuthorizationHeader 获取认证头部信息
func (c *Client) getAuthorizationHeader(ctx context.Context, scope string) (string, error) {
	if c.username == "" || c.password == "" {
		// 没有认证信息，不需要添加认证头部
		return "", nil
	}

	// 尝试从缓存获取 token
	c.cacheMutex.RLock()
	token, exists := c.tokenCache[scope]
	c.cacheMutex.RUnlock()

	// 检查 token 是否存在且未过期
	if exists && token != nil && !token.IsExpired() {
		log.Debug().Str("scope", scope).Msg("使用缓存的 token")
		return "Bearer " + token.Token, nil
	}

	// 获取新的 token
	token, err := c.fetchToken(ctx, scope)
	if err != nil {
		return "", err
	}

	// 缓存 token
	c.cacheMutex.Lock()
	c.tokenCache[scope] = token
	c.cacheMutex.Unlock()

	return "Bearer " + token.Token, nil
}

// fetchToken 从 registry 获取认证 token
func (c *Client) fetchToken(ctx context.Context, scope string) (*Token, error) {
	log.Info().Str("scope", scope).Msg("获取新的认证 token")

	// 构造 token 请求 URL
	tokenURL := fmt.Sprintf("%s/v2/token?service=%s&scope=%s",
		c.registryURL,
		strings.TrimPrefix(c.registryURL, "https://"),
		scope)

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 token 请求失败: %w", err)
	}

	// 添加基本认证
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送 token 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取 token 失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("解析 token 响应失败: %w", err)
	}

	token := &Token{
		Token:       tokenResponse.Token,
		AccessToken: tokenResponse.AccessToken,
		ExpiresIn:   tokenResponse.ExpiresIn,
		IssuedAt:    time.Now(),
	}

	// 设置过期时间
	if token.ExpiresIn > 0 {
		token.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
		// 提前 5 分钟过期以避免边界问题
		token.expiresAt = token.expiresAt.Add(-5 * time.Minute)
	}

	// 如果没有 token 字段，使用 access_token
	if token.Token == "" {
		token.Token = token.AccessToken
	}

	log.Info().Str("token", token.Token).Int("expires_in", token.ExpiresIn).Msg("获取 token 成功")

	return token, nil
}

// doRequest 执行 HTTP 请求，自动处理认证
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body io.Reader, scope string) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.registryURL, endpoint)

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置默认头部
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	// 获取认证头部
	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("获取认证信息失败: %w", err)
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	// 发送请求
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}

	// 处理 401 认证挑战
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()

		// 从 WWW-Authenticate 头部提取 scope
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			parsedScope, err := parseScopeFromWWWAuth(wwwAuth)
			if err == nil && parsedScope != "" {
				// 使用解析出的 scope 重新获取认证信息
				authHeader, err := c.getAuthorizationHeader(ctx, parsedScope)
				if err != nil {
					return nil, fmt.Errorf("获取认证信息失败: %w", err)
				}

				// 重新创建请求并发送
				req, err = http.NewRequestWithContext(ctx, method, url, body)
				if err != nil {
					return nil, fmt.Errorf("创建请求失败: %w", err)
				}

				if body != nil {
					req.Header.Set("Content-Type", "application/octet-stream")
				}

				if authHeader != "" {
					req.Header.Set("Authorization", authHeader)
				}

				return c.client.Do(req)
			}
		}
	}

	return resp, nil
}

// parseScopeFromWWWAuth 从 WWW-Authenticate 头部解析 scope
func parseScopeFromWWWAuth(wwwAuth string) (string, error) {
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("不支持的认证类型: %s", wwwAuth)
	}

	var scope string
	parts := strings.Split(wwwAuth[7:], ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			value := strings.Trim(kv[1], "\"")
			if key == "scope" {
				scope = value
				break
			}
		}
	}

	if scope == "" {
		return "", fmt.Errorf("未找到 scope 信息")
	}

	return scope, nil
}

// UploadLayer 上传 layer 到 registry
func (c *Client) UploadLayer(ctx context.Context, repository, digest string, layerData io.Reader) error {
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	// 第一步：发起上传请求
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v2/%s/blobs/uploads/", repository), nil, scope)
	if err != nil {
		return fmt.Errorf("发起上传请求失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("发起上传请求失败，状态码: %d", resp.StatusCode)
	}

	// 获取上传 URL
	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("响应中未包含 Location 头部")
	}

	// 如果 location 是相对路径，拼接完整 URL
	if strings.HasPrefix(location, "/") {
		location = fmt.Sprintf("%s%s", c.registryURL, location)
	}

	// 第二步：上传数据
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}
	putURL := fmt.Sprintf("%s%sdigest=%s", location, separator, digest)

	putReq, err := http.NewRequestWithContext(ctx, "PUT", putURL, layerData)
	if err != nil {
		return fmt.Errorf("创建 PUT 请求失败: %w", err)
	}

	// 添加认证头部
	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("获取认证信息失败: %w", err)
	}

	if authHeader != "" {
		putReq.Header.Set("Authorization", authHeader)
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := c.client.Do(putReq)
	if err != nil {
		return fmt.Errorf("上传数据失败: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("上传数据失败，状态码: %d", putResp.StatusCode)
	}

	log.Info().Str("digest", digest).Msg("Layer 上传成功")
	return nil
}

// GetManifest 获取镜像 manifest
func (c *Client) GetManifest(ctx context.Context, repository, reference string) ([]byte, string, error) {
	scope := fmt.Sprintf("repository:%s:pull", repository)

	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/v2/%s/manifests/%s", repository, reference), nil, scope)
	if err != nil {
		return nil, "", fmt.Errorf("获取 manifest 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取 manifest 失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取 manifest 内容失败: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	return body, contentType, nil
}

// UploadManifest 上传 manifest 到 registry
func (c *Client) UploadManifest(ctx context.Context, repository, reference string, manifest []byte, contentType string) error {
	scope := fmt.Sprintf("repository:%s:push,pull", repository)

	putURL := fmt.Sprintf("/v2/%s/manifests/%s", repository, reference)
	putReq, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s%s", c.registryURL, putURL), bytes.NewReader(manifest))
	if err != nil {
		return fmt.Errorf("创建 PUT 请求失败: %w", err)
	}

	// 添加认证头部
	authHeader, err := c.getAuthorizationHeader(ctx, scope)
	if err != nil {
		return fmt.Errorf("获取认证信息失败: %w", err)
	}

	if authHeader != "" {
		putReq.Header.Set("Authorization", authHeader)
	}

	// 设置 Content-Type
	if contentType != "" {
		putReq.Header.Set("Content-Type", contentType)
	} else {
		putReq.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	}

	putResp, err := c.client.Do(putReq)
	if err != nil {
		return fmt.Errorf("上传 manifest 失败: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("上传 manifest 失败，状态码: %d, 响应: %s", putResp.StatusCode, string(body))
	}

	log.Info().Str("repository", repository).Str("reference", reference).Msg("Manifest 上传成功")
	return nil
}

// GetBlob 获取 blob 数据
func (c *Client) GetBlob(ctx context.Context, repository, digest string) ([]byte, error) {
	scope := fmt.Sprintf("repository:%s:pull", repository)

	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/v2/%s/blobs/%s", repository, digest), nil, scope)
	if err != nil {
		return nil, fmt.Errorf("获取 blob 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 blob 失败，状态码: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// CalculateSHA256 计算数据的 SHA256 哈希值
func CalculateSHA256(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// CalculateReaderSHA256 计算 reader 数据的 SHA256 哈希值
func CalculateReaderSHA256(reader io.Reader) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
