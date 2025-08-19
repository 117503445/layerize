package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// UploadLayerToRegistryWithAuth 上传层到镜像仓库（带认证）
func UploadLayerToRegistryWithAuth(reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
	// 确保 registryURL 不以 / 结尾
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}

	// 尝试使用 Bearer token 认证
	if username != "" && password != "" {
		log.Info().Str("registryURL", registryURL).Str("repository", repository).Str("username", username).Msg("尝试使用用户名密码上传层")

		// 首先尝试 POST 请求，查看是否需要认证
		postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
		req, err := http.NewRequest("POST", postURL, nil)
		if err != nil {
			return fmt.Errorf("创建POST请求失败: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("POST请求失败: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			if strings.HasPrefix(wwwAuth, "Bearer") {
				// 使用 Bearer token 认证
				token, err := getTokenFromWWWAuth(wwwAuth, username, password)
				if err != nil {
					log.Error().Err(err).Msg("获取token失败")
					return fmt.Errorf("获取token失败: %w", err)
				}
				return uploadLayerWithToken(client, reader, sha256sum, registryURL, repository, token)
			} else {
				// 使用基本认证
				return uploadLayerWithBasicAuth(client, reader, sha256sum, registryURL, repository, username, password)
			}
		} else if resp.StatusCode == http.StatusAccepted {
			// 无需认证，直接上传
			location := resp.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("未获取到Location header")
			}
			return continueUpload(client, reader, sha256sum, registryURL, repository, location)
		} else {
			return fmt.Errorf("POST请求返回意外状态码: %d", resp.StatusCode)
		}
	}

	return fmt.Errorf("需要认证信息")
}

// getTokenFromWWWAuth 从 WWW-Authenticate header 获取 token
func getTokenFromWWWAuth(wwwAuth, username, password string) (string, error) {
	// 解析 WWW-Authenticate header
	// 格式: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
	
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("不支持的认证类型: %s", wwwAuth)
	}

	// 提取参数
	params := strings.Split(wwwAuth[7:], ",")
	var realm, service, scope string

	for _, param := range params {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "realm=") {
			realm = strings.Trim(param[6:], "\"")
		} else if strings.HasPrefix(param, "service=") {
			service = strings.Trim(param[8:], "\"")
		} else if strings.HasPrefix(param, "scope=") {
			scope = strings.Trim(param[6:], "\"")
		}
	}

	if realm == "" {
		return "", fmt.Errorf("未找到realm参数")
	}

	// 构建认证URL
	authURL := realm
	params = []string{}
	if service != "" {
		params = append(params, "service="+url.QueryEscape(service))
	}
	// 对于上传操作，我们需要修改scope以包含push权限
	if scope != "" {
		// 如果原scope只包含pull，我们需要添加push权限
		if strings.Contains(scope, ":pull") && !strings.Contains(scope, ":push") {
			scope = strings.Replace(scope, ":pull", ":push,pull", 1)
		}
		params = append(params, "scope="+url.QueryEscape(scope))
	}

	if len(params) > 0 {
		authURL += "?" + strings.Join(params, "&")
	}

	log.Info().Str("authURL", authURL).Str("scope", scope).Msg("请求认证token")

	// 请求 token
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建认证请求失败: %w", err)
	}

	// 添加基本认证
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("认证请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("认证失败: %s, 响应: %s", resp.Status, string(body))
	}

	// 解析 token 响应
	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("解析token响应失败: %w", err)
	}

	token := tokenResp.Token
	if token == "" {
		token = tokenResp.AccessToken
	}

	if token == "" {
		return "", fmt.Errorf("未获取到有效token")
	}

	log.Info().Msg("成功获取认证token")
	return token, nil
}

// uploadLayerWithToken 使用 token 上传层
func uploadLayerWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, token string) error {
	// 开始上传
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("创建POST请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST请求失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST请求失败，状态码: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("未获取到Location header")
	}

	return continueUploadWithToken(client, reader, sha256sum, registryURL, repository, location, token)
}

// continueUploadWithToken 使用 token 继续上传
func continueUploadWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string, token string) error {
	// 如果 location 是相对路径，转换为绝对路径
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// 添加 digest 参数
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("上传层数据")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("层上传成功")
	return nil
}

// uploadLayerWithBasicAuth 使用基本认证上传层
func uploadLayerWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
	// 开始上传
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("创建POST请求失败: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST请求失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST请求失败，状态码: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("未获取到Location header")
	}

	return continueUpload(client, reader, sha256sum, registryURL, repository, location)
}

// continueUpload 继续上传（无认证）
func continueUpload(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string) error {
	// 如果 location 是相对路径，转换为绝对路径
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// 添加 digest 参数
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("上传层数据")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("层上传成功")
	return nil
}

// continueUploadWithBasicAuth 使用基本认证继续上传
func continueUploadWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location, username, password string) error {
	// 如果 location 是相对路径，转换为绝对路径
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// 添加 digest 参数
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=sha256:" + sha256sum
	} else {
		uploadURL += "?digest=sha256:" + sha256sum
	}

	log.Info().Str("uploadURL", uploadURL).Msg("上传层数据")

	req, err := http.NewRequest("PUT", uploadURL, reader)
	if err != nil {
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("层上传成功")
	return nil
}

// GetManifestWithAuth 获取镜像清单（带认证）
func GetManifestWithAuth(registryURL, repository, reference, username, password string) ([]byte, string, error) {
	// 确保 registryURL 不以 / 结尾
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, reference)

	// 尝试不使用认证
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置 Accept header 以获取正确的 manifest 格式
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("请求失败: %w", err)
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
			// 使用 Bearer token 认证
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				return nil, "", fmt.Errorf("获取token失败: %w", err)
			}
			return getManifestWithToken(client, manifestURL, token)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return nil, "", fmt.Errorf("获取manifest失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
}

// getManifestWithToken 使用 token 获取 manifest
func getManifestWithToken(client *http.Client, manifestURL, token string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("获取manifest失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	return body, contentType, err
}

// getConfigWithAuth 获取镜像配置（带认证）
func GetConfigWithAuth(registryURL, repository, reference, username, password string) ([]byte, error) {
	// 首先获取 manifest
	manifest, _, err := GetManifestWithAuth(registryURL, repository, reference, username, password)
	if err != nil {
		return nil, fmt.Errorf("获取manifest失败: %w", err)
	}

	// 解析 manifest 获取 config 的 digest
	var manifestData map[string]any
	if err := json.Unmarshal(manifest, &manifestData); err != nil {
		return nil, fmt.Errorf("解析manifest失败: %w", err)
	}

	config, ok := manifestData["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("manifest中未找到config字段")
	}

	configDigest, ok := config["digest"].(string)
	if !ok {
		return nil, fmt.Errorf("manifest中未找到config digest")
	}

	// 确保 registryURL 不以 / 结尾
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}
	configURL := fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, repository, configDigest)

	// 尝试不使用认证
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return io.ReadAll(resp.Body)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(wwwAuth, "Bearer") && username != "" && password != "" {
			// 使用 Bearer token 认证
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				return nil, fmt.Errorf("获取token失败: %w", err)
			}
			return getConfigWithToken(client, configURL, token)
		}
	}

	body, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("获取config失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
}

// getConfigWithToken 使用 token 获取 config
func getConfigWithToken(client *http.Client, configURL, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取config失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// UploadConfigToRegistryWithAuth 上传配置到镜像仓库（带认证）
func UploadConfigToRegistryWithAuth(configData []byte, configDigest, registryURL, repository, username, password string) error {
	// 确保 registryURL 不以 / 结尾
	registryURL = strings.TrimSuffix(registryURL, "/")

	client := &http.Client{}

	// 尝试使用 Bearer token 认证
	if username != "" && password != "" {
		log.Info().Str("registryURL", registryURL).Str("repository", repository).Str("username", username).Msg("尝试使用用户名密码上传配置")

		// 首先尝试 POST 请求，查看是否需要认证
		postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
		req, err := http.NewRequest("POST", postURL, nil)
		if err != nil {
			return fmt.Errorf("创建POST请求失败: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("POST请求失败: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			if strings.HasPrefix(wwwAuth, "Bearer") {
				// 使用 Bearer token 认证
				token, err := getTokenFromWWWAuth(wwwAuth, username, password)
				if err != nil {
					log.Error().Err(err).Msg("获取token失败")
					return fmt.Errorf("获取token失败: %w", err)
				}
				return uploadConfigWithToken(client, configData, configDigest, registryURL, repository, token)
			} else {
				// 使用基本认证
				return uploadConfigWithBasicAuth(client, configData, configDigest, registryURL, repository, username, password)
			}
		} else if resp.StatusCode == http.StatusAccepted {
			// 无需认证，直接上传
			location := resp.Header.Get("Location")
			if location == "" {
				return fmt.Errorf("未获取到Location header")
			}
			return continueConfigUploadWithBasicAuth(client, configData, configDigest, registryURL, repository, location, username, password)
		} else {
			return fmt.Errorf("POST请求返回意外状态码: %d", resp.StatusCode)
		}
	}

	return fmt.Errorf("需要认证信息")
}

// uploadConfigWithBasicAuth 使用基本认证上传配置
func uploadConfigWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, username, password string) error {
	// 开始上传
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("创建POST请求失败: %w", err)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST请求失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST请求失败，状态码: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("未获取到Location header")
	}

	return continueConfigUploadWithBasicAuth(client, configData, configDigest, registryURL, repository, location, username, password)
}

// uploadConfigWithToken 使用 token 上传配置
func uploadConfigWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, token string) error {
	// 开始上传
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	req, err := http.NewRequest("POST", postURL, nil)
	if err != nil {
		return fmt.Errorf("创建POST请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST请求失败: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST请求失败，状态码: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("未获取到Location header")
	}

	return continueConfigUploadWithToken(client, configData, configDigest, registryURL, repository, location, token)
}

// continueConfigUploadWithBasicAuth 使用基本认证继续上传配置
func continueConfigUploadWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, location, username, password string) error {
	// 如果 location 是相对路径，转换为绝对路径
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// 添加 digest 参数
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=" + configDigest
	} else {
		uploadURL += "?digest=" + configDigest
	}

	log.Info().Str("uploadURL", uploadURL).Msg("上传配置数据")

	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(configData)))
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("配置上传成功")
	return nil
}

// continueConfigUploadWithToken 使用 token 继续上传配置
func continueConfigUploadWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, location, token string) error {
	// 如果 location 是相对路径，转换为绝对路径
	uploadURL := location
	if strings.HasPrefix(location, "/") {
		uploadURL = registryURL + location
	}

	// 添加 digest 参数
	if strings.Contains(uploadURL, "?") {
		uploadURL += "&digest=" + configDigest
	} else {
		uploadURL += "?digest=" + configDigest
	}

	log.Info().Str("uploadURL", uploadURL).Msg("上传配置数据")

	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(configData))
	if err != nil {
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(configData)))
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}

	log.Info().Msg("配置上传成功")
	return nil
}