package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

func compressToTarGz(sourceDir, outputTarGz string) error {
	// if err := compressToTarGz("tmp", "tmp.tar.gz"); err != nil {
	// 	log.Panic().Err(err).Msg("打包失败")
	// }

	// 检查源目录是否存在
	info, err := os.Stat(sourceDir)
	if os.IsNotExist(err) {
		log.Error().Str("path", sourceDir).Msg("源目录不存在")
		return fmt.Errorf("源目录不存在: %s", sourceDir)
	}
	if !info.IsDir() {
		log.Error().Str("path", sourceDir).Msg("源路径不是目录")
		return fmt.Errorf("源路径不是目录: %s", sourceDir)
	}

	log.Info().
		Str("source", sourceDir).
		Str("output", outputTarGz).
		Msg("compressToTarGz")

	// 构建 tar 命令
	// tar -czf output.tar.gz -C /path/to/source .
	cmd := exec.Command("tar", "-czf", outputTarGz, "-C", sourceDir, ".")

	// 捕获命令的标准输出和错误（可选）
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 执行命令
	err = cmd.Run()
	if err != nil {
		log.Error().
			Err(err).
			Str("command", cmd.String()).
			Msg("执行 tar 命令失败")
		return fmt.Errorf("执行 tar 命令失败: %w", err)
	}

	log.Info().
		Str("output", outputTarGz).
		Dur("duration", cmd.ProcessState.UserTime()).
		Msg("打包成功")

	return nil
}

// getContentLength 获取reader的内容长度（如果可能）
func getContentLength(reader io.Reader) int64 {
	// 如果reader实现了Sizer接口，则直接获取大小
	if s, ok := reader.(interface{ Size() int64 }); ok {
		return s.Size()
	}

	// 如果是*os.File类型，可以通过Stat获取大小
	if f, ok := reader.(*os.File); ok {
		if stat, err := f.Stat(); err == nil {
			return stat.Size()
		}
	}

	// 无法确定大小
	return 0
}

// CalculateFileSHA256 计算指定文件的 SHA256 哈希值
func CalculateFileSHA256(filePath string) (string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Str("path", filePath).Msg("无法打开文件")
		return "", fmt.Errorf("无法打开文件 %s: %w", filePath, err)
	}
	defer file.Close()

	// 创建一个新的 SHA256 hasher
	hasher := sha256.New()

	// 将文件内容复制到 hasher
	if _, err := io.Copy(hasher, file); err != nil {
		log.Error().Err(err).Str("path", filePath).Msg("读取文件时出错")
		return "", fmt.Errorf("读取文件 %s 时出错: %w", filePath, err)
	}

	// 计算哈希值并返回十六进制表示
	hashBytes := hasher.Sum(nil)
	return fmt.Sprintf("%x", hashBytes), nil
}

// UploadLayerToRegistry 上传layer到镜像仓库
// reader: layer数据的io.Reader
// sha256sum: layer的sha256摘要
// registryURL: 镜像仓库URL (例如: "http://localhost:5000")
// repository: 镜像仓库中的repository名称 (例如: "myapp")
func UploadLayerToRegistry(reader io.Reader, sha256sum, registryURL, repository string) error {
	return UploadLayerToRegistryWithAuth(reader, sha256sum, registryURL, repository, "", "")
}

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

	// 添加认证信息
	// if username != "" && password != "" {
	// 	req.SetBasicAuth(username, password)
	// }

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
				log.Error().Err(err).Msg("获取token失败")
				return fmt.Errorf("获取token失败: %w", err)
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

	log.Info().
		Str("realm", realm).
		Str("service", service).
		Str("scope", scope).
		Msg("解析认证参数")

	// 构造token请求URL
	tokenURL := fmt.Sprintf("%s?service=%s&scope=%s", realm, service, scope)

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
		log.Error().Int("status", resp.StatusCode).Msg("获取token返回错误状态码")
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
	return continueUpload(client, reader, sha256sum, registryURL, repository, resp.Header.Get("Location"))
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

	// 添加认证信息
	// if username != "" && password != "" {
	// 	putReq.SetBasicAuth(username, password)
	// }

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

// GetDockerHubToken 从Docker Hub获取token
// username: Docker Hub用户名
// password: Docker Hub密码
// repository: 镜像仓库名称，例如"library/ubuntu"
// scope: 访问权限范围，例如"pull"
func GetDockerHubToken(username, password, repository, scope string) (string, error) {
	// 构造获取token的URL
	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:%s", repository, scope)

	log.Info().Str("url", url).Msg("正在获取Docker Hub token")

	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error().Err(err).Msg("创建获取token请求失败")
		return "", fmt.Errorf("创建获取token请求失败: %w", err)
	}

	// 添加Basic认证信息
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
		log.Error().Int("status", resp.StatusCode).Msg("获取token返回错误状态码")
		return "", fmt.Errorf("获取token返回错误状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("读取响应内容失败")
		return "", fmt.Errorf("读取响应内容失败: %w", err)
	}

	log.Info().Str("response", string(body)).Msg("获取token成功")

	// 这里应该解析JSON响应并提取token
	// 简单起见，我们直接返回响应体
	// 实际使用时应该解析JSON并提取token字段
	return string(body), nil
}
