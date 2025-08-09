package main

import (
	"crypto/sha256"
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
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode != http.StatusAccepted {
		log.Error().Int("status", resp.StatusCode).Msg("上传请求返回错误状态码")
		return fmt.Errorf("上传请求返回错误状态码: %d", resp.StatusCode)
	}

	// 获取上传URL
	location := resp.Header.Get("Location")
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
	if username != "" && password != "" {
		putReq.SetBasicAuth(username, password)
	}

	putReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err = client.Do(putReq)
	if err != nil {
		log.Error().Err(err).Msg("上传数据失败")
		return fmt.Errorf("上传数据失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		log.Error().Int("status", resp.StatusCode).Msg("上传数据返回错误状态码")
		return fmt.Errorf("上传数据返回错误状态码: %d", resp.StatusCode)
	}

	log.Info().Str("sha256", sha256sum).Msg("layer上传成功")
	return nil

}
