package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// UploadLayerToRegistryWithAuth 上传layer到镜像仓库（带认证）
// reader: layer数据的io.Reader
// sha256sum: layer的sha256摘要
// registryURL: 镜像仓库URL (例如: "http://localhost:5000")
// repository: 镜像仓库中的repository名称 (例如: "myapp")
// username: 认证用户名
// password: 认证密码
func UploadLayerToRegistryWithAuth(reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
	// 第一步：发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)

	log.Info().Str("url", uploadURL).Msg("开始上传layer")

	// 创建请求
	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传请求失败")
		return fmt.Errorf("创建上传请求失败: %w", err)
	}

	// 添加认证信息（如果提供了用户名和密码）
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// 发起POST请求启动上传过程
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传请求失败")
		return fmt.Errorf("发起上传请求失败: %w", err)
	}
	resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Info().Str("WWW-Authenticate", wwwAuth).Msg("收到认证挑战")

			// 解析WWW-Authenticate头部获取token
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				log.Warn().Err(err).Msg("获取token失败，尝试使用基础认证")
				// 如果获取token失败，尝试使用基础认证重新上传
				return uploadLayerWithBasicAuth(client, reader, sha256sum, registryURL, repository, username, password)
			}

			// 使用token重新发起上传请求
			return uploadLayerWithToken(client, reader, sha256sum, registryURL, repository, token)
		}
		log.Error().Int("status", resp.StatusCode).Msg("未提供认证信息")
		return fmt.Errorf("认证失败: %d", resp.StatusCode)
	} else if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传请求返回错误状态码")
		}
		return fmt.Errorf("上传请求返回错误状态码: %d", resp.StatusCode)
	} else {
		// 继续上传流程
		return continueUpload(client, reader, sha256sum, registryURL, repository, resp.Header.Get("Location"))
	}
}

// 解析WWW-Authenticate头部并获取token
func getTokenFromWWWAuth(wwwAuth, username, password string) (string, error) {
	// 解析WWW-Authenticate头部，例如:
	// Bearer realm="https://cr.console.aliyun.com/v1/token",service="registry.cn-hangzhou.aliyuncs.com",scope="repository:117503445/layerize-test-base:push,pull"

	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("不支持的认证类型: %s", wwwAuth)
	}

	// 提取realm, service, scope参数
	var realm, service, scope string
	parts := strings.Split(wwwAuth[7:], ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			// 去掉引号
			value := strings.Trim(kv[1], "\"")
			switch key {
			case "realm":
				realm = value
			case "service":
				service = value
			case "scope":
				scope = value
			}
		}
	}
	// repo := parts[1]
	// desiredScope := fmt.Sprintf("%s:pull,push", repo)
	// scope = "push"
	desiredScope := "repository:117503445/layerize-test-base:pull,push" // TODO

	log.Info().
		Str("realm", realm).
		Str("service", service).
		Str("scope", scope).
		Str("desiredScope", desiredScope).
		Msg("解析认证参数")

	// 构造token请求URL
	tokenURL := fmt.Sprintf("%s?service=%s&scope=%s", realm, service, desiredScope)

	log.Info().Str("url", tokenURL).Msg("正在获取Bearer Token")

	// 创建请求
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取token请求失败")
		return "", fmt.Errorf("创建获取token请求失败: %w", err)
	}

	// 添加Basic认证信息（使用阿里云的AccessKey ID和AccessKey Secret）
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发送获取token请求失败")
		return "", fmt.Errorf("发送获取token请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("读取响应内容失败")
		}

		log.Error().Int("status", resp.StatusCode).
			Interface("body", string(body)).
			Msg("获取token返回错误状态码")
		return "", fmt.Errorf("获取token返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取响应内容失败")
		return "", fmt.Errorf("读取响应内容失败: %w", err)
	}

	// 解析JSON响应提取token
	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IssuedAt    string `json:"issued_at"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Error().Err(err).Str("body", string(body)).Msg("解析token响应失败")
		return "", fmt.Errorf("解析token响应失败: %w", err)
	}

	token := tokenResponse.Token
	if token == "" {
		token = tokenResponse.AccessToken
	}

	if token == "" {
		log.Error().Str("body", string(body)).Msg("响应中未找到token")
		return "", fmt.Errorf("响应中未找到token")
	}

	log.Info().Str("token", token).Msg("获取Bearer Token成功")

	return token, nil
}

// 使用token继续上传流程
func uploadLayerWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, token string) error {
	log.Info().
		Str("sha256", sha256sum).
		Str("registry", registryURL).
		Str("repository", repository).
		Str("token", token).
		Msg("开始上传layer")

	// 重新发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	log.Debug().Str("url", uploadURL).Msg("正在发起上传请求")

	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传请求失败")
		return fmt.Errorf("创建上传请求失败: %w", err)
	}

	// 添加Bearer Token认证
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")

	log.Debug().Interface("req.Header", req.Header).Send()

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传请求失败")
		return fmt.Errorf("发起上传请求失败: %w", err)
	}
	resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传请求返回错误状态码")
		}
		return fmt.Errorf("上传请求返回错误状态码: %d", resp.StatusCode)
	}

	// 继续上传流程
	return continueUploadWithToken(client, reader, sha256sum, registryURL, repository, resp.Header.Get("Location"), token)
}

// 使用token继续上传流程
func continueUploadWithToken(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string, token string) error {
	// 获取上传URL
	if location == "" {
		log.Error().Msg("响应中未包含Location头部")
		return fmt.Errorf("响应中未包含Location头部")
	}

	// 如果location是相对路径，则需要拼接完整URL
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}

	log.Info().Str("location", location).Msg("获得上传地址")

	// 第二步：上传数据
	// 使用PUT方法上传数据，并在URL中指定digest
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}
	putURL := fmt.Sprintf("%s%sdigest=sha256:%s", location, separator, sha256sum)

	putReq, err := http.NewRequest("PUT", putURL, reader)
	if err != nil {
		log.Error().Err(err).Msg("创建PUT请求失败")
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	// 添加Bearer Token认证
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传数据失败")
		return fmt.Errorf("上传数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传数据返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传数据返回错误状态码")
		}
		return fmt.Errorf("上传数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("sha256", sha256sum).Msg("layer上传成功")
	return nil
}

// 使用基础认证继续上传流程
func uploadLayerWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, username, password string) error {
	log.Info().
		Str("sha256", sha256sum).
		Str("registry", registryURL).
		Str("repository", repository).
		Msg("开始使用基础认证上传layer")

	// 发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	log.Debug().Str("url", uploadURL).Msg("正在发起上传请求")

	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传请求失败")
		return fmt.Errorf("创建上传请求失败: %w", err)
	}

	// 添加基础认证信息
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传请求失败")
		return fmt.Errorf("发起上传请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传请求返回错误状态码")
		}
		return fmt.Errorf("上传请求返回错误状态码: %d", resp.StatusCode)
	}

	// 继续上传流程
	return continueUploadWithBasicAuth(client, reader, sha256sum, registryURL, repository, resp.Header.Get("Location"), username, password)
}

// 继续上传流程
func continueUpload(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location string) error {
	// 获取上传URL
	if location == "" {
		log.Error().Msg("响应中未包含Location头部")
		return fmt.Errorf("响应中未包含Location头部")
	}

	// 如果location是相对路径，则需要拼接完整URL
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}

	log.Info().Str("location", location).Msg("获得上传地址")

	// 第二步：上传数据
	// 使用PUT方法上传数据，并在URL中指定digest
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}
	putURL := fmt.Sprintf("%s%sdigest=sha256:%s", location, separator, sha256sum)

	putReq, err := http.NewRequest("PUT", putURL, reader)
	if err != nil {
		log.Error().Err(err).Msg("创建PUT请求失败")
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传数据失败")
		return fmt.Errorf("上传数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传数据返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传数据返回错误状态码")
		}
		return fmt.Errorf("上传数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("sha256", sha256sum).Msg("layer上传成功")
	return nil

}

// 继续上传流程（带基础认证）
func continueUploadWithBasicAuth(client *http.Client, reader io.Reader, sha256sum, registryURL, repository, location, username, password string) error {
	// 获取上传URL
	if location == "" {
		log.Error().Msg("响应中未包含Location头部")
		return fmt.Errorf("响应中未包含Location头部")
	}

	// 如果location是相对路径，则需要拼接完整URL
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}

	log.Info().Str("location", location).Msg("获得上传地址")

	// 第二步：上传数据
	// 使用PUT方法上传数据，并在URL中指定digest
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}
	putURL := fmt.Sprintf("%s%sdigest=sha256:%s", location, separator, sha256sum)

	putReq, err := http.NewRequest("PUT", putURL, reader)
	if err != nil {
		log.Error().Err(err).Msg("创建PUT请求失败")
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	// 添加基础认证信息
	if username != "" && password != "" {
		putReq.SetBasicAuth(username, password)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传数据失败")
		return fmt.Errorf("上传数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传数据返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传数据返回错误状态码")
		}
		return fmt.Errorf("上传数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("sha256", sha256sum).Msg("layer上传成功")
	return nil

}

// GetManifestWithAuth 获取镜像的manifest（带认证）
// registryURL: 镜像仓库URL (例如: "http://localhost:5000")
// repository: 镜像仓库中的repository名称 (例如: "myapp")
// reference: 镜像tag或digest (例如: "latest" 或 "sha256:...")
// username: 认证用户名
// password: 认证密码
func GetManifestWithAuth(registryURL, repository, reference, username, password string) ([]byte, string, error) {
	// 构造获取manifest的URL
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, reference)

	log.Info().Str("url", manifestURL).Msg("开始获取manifest")

	// 创建请求
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取manifest请求失败")
		return nil, "", fmt.Errorf("创建获取manifest请求失败: %w", err)
	}

	// 设置Accept头部，支持多种media type
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")

	// 添加认证信息（如果提供了用户名和密码）
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// 发起GET请求获取manifest
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起获取manifest请求失败")
		return nil, "", fmt.Errorf("发起获取manifest请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Info().Str("WWW-Authenticate", wwwAuth).Msg("收到认证挑战")

			// 解析WWW-Authenticate头部获取token
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				log.Warn().Err(err).Msg("获取token失败")
				return nil, "", fmt.Errorf("获取token失败: %w", err)
			}

			// 使用token重新发起请求
			return getManifestWithToken(client, manifestURL, token)
		}
		log.Error().Int("status", resp.StatusCode).Msg("未提供认证信息")
		return nil, "", fmt.Errorf("认证失败: %d", resp.StatusCode)
	} else if resp.StatusCode != http.StatusOK {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("获取manifest返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("获取manifest返回错误状态码")
		}
		return nil, "", fmt.Errorf("获取manifest返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取manifest内容失败")
		return nil, "", fmt.Errorf("读取manifest内容失败: %w", err)
	}

	// 获取Content-Type头部
	contentType := resp.Header.Get("Content-Type")

	log.Info().Str("contentType", contentType).Msg("获取manifest成功")

	return body, contentType, nil
}

// 使用token获取manifest
func getManifestWithToken(client *http.Client, manifestURL, token string) ([]byte, string, error) {
	log.Info().Str("url", manifestURL).Msg("使用token获取manifest")

	// 创建请求
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取manifest请求失败")
		return nil, "", fmt.Errorf("创建获取manifest请求失败: %w", err)
	}

	// 设置Accept头部，支持多种media type
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")

	// 添加Bearer Token认证
	req.Header.Set("Authorization", "Bearer "+token)

	// 发起GET请求获取manifest
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起获取manifest请求失败")
		return nil, "", fmt.Errorf("发起获取manifest请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("获取manifest返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("获取manifest返回错误状态码")
		}
		return nil, "", fmt.Errorf("获取manifest返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取manifest内容失败")
		return nil, "", fmt.Errorf("读取manifest内容失败: %w", err)
	}

	// 获取Content-Type头部
	contentType := resp.Header.Get("Content-Type")

	log.Info().Str("contentType", contentType).Msg("获取manifest成功")

	return body, contentType, nil
}

// GetConfigWithAuth 从镜像仓库获取镜像配置信息
// registryURL: 镜像仓库URL (例如: "https://registry.cn-hangzhou.aliyuncs.com")
// repository: 镜像仓库中的repository名称 (例如: "117503445/layerize-test-base")
// reference: 镜像标签 (例如: "latest")
// username: 认证用户名
// password: 认证密码
func getConfigWithAuth(registryURL, repository, reference, username, password string) ([]byte, error) {
	// 首先获取manifest
	manifestData, _, err := GetManifestWithAuth(registryURL, repository, reference, username, password)
	if err != nil {
		return nil, fmt.Errorf("获取manifest失败: %w", err)
	}

	// 解析manifest获取config digest
	var manifest OCIManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("解析manifest失败: %w", err)
	}

	configDigest := manifest.Config.Digest

	// 构造获取config的URL
	configURL := fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, repository, configDigest)

	log.Info().Str("url", configURL).Msg("开始获取config")

	// 创建请求
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取config请求失败")
		return nil, fmt.Errorf("创建获取config请求失败: %w", err)
	}

	// 添加认证信息（如果提供了用户名和密码）
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// 设置Accept头部
	req.Header.Set("Accept", "application/vnd.docker.container.image.v1+json, application/vnd.oci.image.config.v1+json")

	// 发起GET请求获取config
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起获取config请求失败")
		return nil, fmt.Errorf("发起获取config请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Info().Str("WWW-Authenticate", wwwAuth).Msg("收到认证挑战")

			// 解析WWW-Authenticate头部获取token
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				log.Warn().Err(err).Msg("获取token失败")
				return nil, fmt.Errorf("获取token失败: %w", err)
			}

			// 使用token重新发起请求
			return getConfigWithToken(client, configURL, token)
		}
		log.Error().Int("status", resp.StatusCode).Msg("未提供认证信息")
		return nil, fmt.Errorf("认证失败: %d", resp.StatusCode)
	} else if resp.StatusCode != http.StatusOK {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("获取config返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("获取config返回错误状态码")
		}
		return nil, fmt.Errorf("获取config返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取config内容失败")
		return nil, fmt.Errorf("读取config内容失败: %w", err)
	}

	log.Info().Str("digest", configDigest).Int("size", len(body)).Msg("获取config成功")

	return body, nil
}

// 使用token获取config
func getConfigWithToken(client *http.Client, configURL, token string) ([]byte, error) {
	// 创建请求
	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取config请求失败")
		return nil, fmt.Errorf("创建获取config请求失败: %w", err)
	}

	// 设置Authorization头部
	req.Header.Set("Authorization", "Bearer "+token)

	// 设置Accept头部
	req.Header.Set("Accept", "application/vnd.docker.container.image.v1+json, application/vnd.oci.image.config.v1+json")

	// 发起GET请求获取config
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起获取config请求失败")
		return nil, fmt.Errorf("发起获取config请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status", resp.StatusCode).Msg("获取config返回错误状态码")
		return nil, fmt.Errorf("获取config返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取config内容失败")
		return nil, fmt.Errorf("读取config内容失败: %w", err)
	}

	log.Info().Int("size", len(body)).Msg("获取config成功")

	return body, nil
}

// UploadConfigToRegistryWithAuth 上传更新后的镜像配置到镜像仓库
// configData: 更新后的配置数据
// configDigest: 配置的SHA256摘要 (格式: "sha256:...")
// registryURL: 镜像仓库URL (例如: "https://registry.cn-hangzhou.aliyuncs.com")
// repository: 镜像仓库中的repository名称 (例如: "117503445/layerize-test-base")
// username: 认证用户名
// password: 认证密码
func uploadConfigToRegistryWithAuth(configData []byte, configDigest, registryURL, repository, username, password string) error {
	// 第一步：发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)

	log.Info().Str("url", uploadURL).Msg("开始上传config")

	// 创建请求
	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传config请求失败")
		return fmt.Errorf("创建上传config请求失败: %w", err)
	}

	// 添加认证信息（如果提供了用户名和密码）
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// 发起POST请求启动上传过程
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传config请求失败")
		return fmt.Errorf("发起上传config请求失败: %w", err)
	}
	resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Info().Str("WWW-Authenticate", wwwAuth).Msg("收到认证挑战")

			// 解析WWW-Authenticate头部获取token
			token, err := getTokenFromWWWAuth(wwwAuth, username, password)
			if err != nil {
				log.Warn().Err(err).Msg("获取token失败，尝试使用基础认证")
				// 如果获取token失败，尝试使用基础认证重新上传
				return uploadConfigWithBasicAuth(client, configData, configDigest, registryURL, repository, username, password)
			}

			// 使用token重新发起上传请求
			return uploadConfigWithToken(client, configData, configDigest, registryURL, repository, token)
		}
		log.Error().Int("status", resp.StatusCode).Msg("未提供认证信息")
		return fmt.Errorf("认证失败: %d", resp.StatusCode)
	} else if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传config请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传config请求返回错误状态码")
		}
		return fmt.Errorf("上传config请求返回错误状态码: %d", resp.StatusCode)
	} else {
		// 继续上传流程
		return continueConfigUploadWithBasicAuth(client, configData, configDigest, registryURL, repository, resp.Header.Get("Location"), username, password)
	}
}

// 使用基础认证继续上传配置流程
func uploadConfigWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, username, password string) error {
	log.Info().
		Str("digest", configDigest).
		Str("registry", registryURL).
		Str("repository", repository).
		Msg("开始使用基础认证上传config")

	// 发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	log.Debug().Str("url", uploadURL).Msg("正在发起上传config请求")

	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传config请求失败")
		return fmt.Errorf("创建上传config请求失败: %w", err)
	}

	// 添加基础认证信息
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传config请求失败")
		return fmt.Errorf("发起上传config请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传config请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传config请求返回错误状态码")
		}
		return fmt.Errorf("上传config请求返回错误状态码: %d", resp.StatusCode)
	}

	// 继续上传流程
	return continueConfigUploadWithBasicAuth(client, configData, configDigest, registryURL, repository, resp.Header.Get("Location"), username, password)
}

// 使用token上传配置
func uploadConfigWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, token string) error {
	log.Info().
		Str("digest", configDigest).
		Str("registry", registryURL).
		Str("repository", repository).
		Str("token", token).
		Msg("开始上传config")

	// 重新发起上传请求
	uploadURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", registryURL, repository)
	log.Debug().Str("url", uploadURL).Msg("正在发起上传config请求")

	req, err := http.NewRequest("POST", uploadURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建上传config请求失败")
		return fmt.Errorf("创建上传config请求失败: %w", err)
	}

	// 添加Bearer Token认证
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")

	log.Debug().Interface("req.Header", req.Header).Send()

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("发起上传config请求失败")
		return fmt.Errorf("发起上传config请求失败: %w", err)
	}
	resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusAccepted {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传config请求返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传config请求返回错误状态码")
		}
		return fmt.Errorf("上传config请求返回错误状态码: %d", resp.StatusCode)
	}

	// 继续上传流程
	return continueConfigUploadWithToken(client, configData, configDigest, registryURL, repository, resp.Header.Get("Location"), token)
}

// 继续上传配置流程（带基础认证）
func continueConfigUploadWithBasicAuth(client *http.Client, configData []byte, configDigest, registryURL, repository, location, username, password string) error {
	// 获取上传URL
	if location == "" {
		log.Error().Msg("响应中未包含Location头部")
		return fmt.Errorf("响应中未包含Location头部")
	}

	// 如果location是相对路径，则需要拼接完整URL
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}

	log.Info().Str("location", location).Msg("获得上传config地址")

	// 第二步：上传数据
	// 使用PUT方法上传数据，并在URL中指定digest
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}

	// 确保digest格式正确
	digest := configDigest
	if strings.HasPrefix(digest, "sha256:") {
		digest = digest[7:] // 移除 "sha256:" 前缀
	}

	putURL := fmt.Sprintf("%s%sdigest=sha256:%s", location, separator, digest)

	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(configData))
	if err != nil {
		log.Error().Err(err).Msg("创建PUT请求失败")
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	// 添加基础认证信息
	if username != "" && password != "" {
		putReq.SetBasicAuth(username, password)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(configData)))

	resp, err := client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传config数据失败")
		return fmt.Errorf("上传config数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传config数据返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传config数据返回错误状态码")
		}
		return fmt.Errorf("上传config数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("digest", configDigest).Msg("config上传成功")
	return nil
}

// 继续上传配置流程（带token认证）
func continueConfigUploadWithToken(client *http.Client, configData []byte, configDigest, registryURL, repository, location, token string) error {
	// 获取上传URL
	if location == "" {
		log.Error().Msg("响应中未包含Location头部")
		return fmt.Errorf("响应中未包含Location头部")
	}

	// 如果location是相对路径，则需要拼接完整URL
	if strings.HasPrefix(location, "/") {
		location = registryURL + location
	}

	log.Info().Str("location", location).Msg("获得上传config地址")

	// 第二步：上传数据
	// 使用PUT方法上传数据，并在URL中指定digest
	separator := "?"
	if strings.Contains(location, "?") {
		separator = "&"
	}

	// 确保digest格式正确
	digest := configDigest
	if strings.HasPrefix(digest, "sha256:") {
		digest = digest[7:] // 移除 "sha256:" 前缀
	}

	putURL := fmt.Sprintf("%s%sdigest=sha256:%s", location, separator, digest)

	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(configData))
	if err != nil {
		log.Error().Err(err).Msg("创建PUT请求失败")
		return fmt.Errorf("创建PUT请求失败: %w", err)
	}

	// 添加Bearer Token认证
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(configData)))

	resp, err := client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传config数据失败")
		return fmt.Errorf("上传config数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth != "" {
			log.Error().Int("status", resp.StatusCode).Str("WWW-Authenticate", wwwAuth).Msg("上传config数据返回错误状态码")
		} else {
			log.Error().Int("status", resp.StatusCode).Msg("上传config数据返回错误状态码")
		}
		return fmt.Errorf("上传config数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("digest", configDigest).Msg("config上传成功")
	return nil
}