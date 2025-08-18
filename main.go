package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/117503445/goutils"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

// Auth 用于存储认证信息
type Auth struct {
	Username string
	Password string
}

// BuildImageParams 用于存储 BuildImage 函数的参数
type BuildImageParams struct {
	BaseImageName   string
	BaseImageAuth   Auth
	DiffTarGzReader io.Reader
	DiffTarLen      int64
	TargetImage     string
	TargetAuth      Auth
}

// BuildImage 封装了构建镜像的完整流程
// 参数:
// - params: BuildImageParams 结构体，包含构建镜像所需的所有参数
func BuildImage(params BuildImageParams) error {
	goutils.InitZeroLog()

	// 获取 diff.tar 的内容
	diffTarData, err := io.ReadAll(params.DiffTarGzReader)
	if err != nil {
		log.Error().Err(err).Msg("读取diffTarGzReader失败")
		return err
	}

	// 计算 diff.tar 的 SHA256 用作 diffID
	diffSha256sum, err := CalculateDataSHA256(diffTarData)
	if err != nil {
		log.Error().Err(err).Msg("计算diff.tar SHA256失败")
		return err
	}

	// 创建临时文件用于上传
	tmpFile, err := os.CreateTemp("", "diff.tar.gz")
	if err != nil {
		log.Error().Err(err).Msg("创建临时文件失败")
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 直接将diffTarData写入临时文件，因为已经是压缩格式
	if _, err := tmpFile.Write(diffTarData); err != nil {
		log.Error().Err(err).Msg("写入临时文件失败")
		return err
	}

	// 如果需要重新定位文件指针到开始位置
	if _, err := tmpFile.Seek(0, 0); err != nil {
		log.Error().Err(err).Msg("重置文件指针失败")
		return err
	}

	// 获取压缩文件信息
	fileSize := params.DiffTarLen

	// 重新打开文件用于上传
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		log.Error().Err(err).Msg("重新打开临时文件失败")
		return err
	}
	defer file.Close()

	// 计算压缩文件的SHA256
	sha256sum, err := CalculateFileSHA256(tmpFile.Name())
	if err != nil {
		log.Error().Err(err).Msg("计算压缩文件SHA256失败")
		return err
	}

	// 上传 layer 到目标镜像仓库
	err = UploadLayerToRegistryWithAuth(file, sha256sum, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("UploadLayerToRegistryWithAuth failed")
		return err
	}

	log.Info().Msg("文件上传完成")

	// 声明 updatedConfig 变量
	var updatedConfig []byte

	// 获取基础镜像配置信息
	config, err := GetConfigWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, "latest", params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("获取config失败")
		return err
	}

	log.Info().Int("configSize", len(config)).Msg("获取config成功")
	log.Debug().RawJSON("config", config).Msg("config内容")

	// 调用 UpdateOCIConfig 更新config，使用 diff.tar 的 sha256 作为 diffID
	updatedConfig, err = UpdateOCIConfig(config, "sha256:"+diffSha256sum)
	if err != nil {
		log.Error().Err(err).Msg("更新config失败")
		return err
	}

	log.Info().Int("updatedConfigSize", len(updatedConfig)).Msg("更新config成功")
	log.Debug().RawJSON("updatedConfig", updatedConfig).Msg("更新后的config内容")

	// 上传更新后的配置
	err = UploadUpdatedConfigToRegistry(updatedConfig, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("上传更新后的config失败")
		return err
	}

	log.Info().Msg("上传更新后的config成功")

	// 获取基础镜像manifest示例
	manifest, contentType, err := GetManifestWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, "latest", params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("获取manifest失败")
		return err
	}

	log.Info().Str("contentType", contentType).Int("manifestSize", len(manifest)).Msg("获取manifest成功")
	// 如果需要查看manifest内容，可以取消下面的注释
	log.Debug().RawJSON("manifest", manifest).Msg("manifest内容")

	// 计算更新后配置的SHA256摘要
	configSHA256, err := CalculateDataSHA256(updatedConfig)
	if err != nil {
		log.Error().Err(err).Msg("计算配置SHA256失败")
		return err
	}
	configDigest := "sha256:" + configSHA256

	// 更新 manifest 中的配置引用
	var manifestData map[string]any
	if err := json.Unmarshal(manifest, &manifestData); err != nil {
		log.Error().Err(err).Msg("解析manifest失败")
		return err
	}

	if config, ok := manifestData["config"].(map[string]any); ok {
		config["digest"] = configDigest
		// 重新计算配置大小
		config["size"] = len(updatedConfig)
	}

	// 重新序列化 manifest
	updatedManifestWithNewConfig, err := json.Marshal(manifestData)
	if err != nil {
		log.Error().Err(err).Msg("序列化更新后的manifest失败")
		return err
	}

	// 调用 updateOCIManifest 更新manifest
	updatedManifest, err := updateOCIManifest(updatedManifestWithNewConfig, "sha256:"+sha256sum, fileSize, "")
	if err != nil {
		log.Error().Err(err).Msg("更新manifest失败")
		return err
	}

	log.Info().Int("updatedManifestSize", len(updatedManifest)).Msg("更新manifest成功")
	log.Debug().RawJSON("updatedManifest", updatedManifest).Msg("更新后的manifest内容")

	// 上传更新后的manifest到目标仓库
	client := NewClient("https://registry.cn-hangzhou.aliyuncs.com", params.TargetAuth.Username, params.TargetAuth.Password)
	err = client.UploadManifest(context.Background(), params.TargetImage, "latest", updatedManifest, contentType)
	if err != nil {
		log.Error().Err(err).Msg("上传更新后的manifest失败")
		return err
	}

	log.Info().Msg("上传更新后的manifest成功")
	return nil
}

func main() {
	goutils.InitZeroLog()

	// 加载 .env 文件
	err := godotenv.Load()
	if err != nil {
		log.Error().Err(err).Msg("加载 .env 文件失败")
		panic(err)
	}

	// 从环境变量读取认证信息
	username := os.Getenv("username")
	password := os.Getenv("password")
	auth := Auth{Username: username, Password: password}

	// 打开 diff.tar 文件
	diffTarFile, err := os.Open("./tmp/diff.tar")
	if err != nil {
		log.Error().Err(err).Msg("打开 diff.tar 文件失败")
		panic(err)
	}
	defer diffTarFile.Close()

	// 获取 diff.tar 文件信息用于长度
	diffTarFileInfo, err := diffTarFile.Stat()
	if err != nil {
		log.Error().Err(err).Msg("获取 diff.tar 文件信息失败")
		panic(err)
	}

	// 调用 BuildImage 函数执行构建操作
	params := BuildImageParams{
		BaseImageName:   "117503445/layerize-test-base", // base image name
		BaseImageAuth:   auth,                           // base image auth
		DiffTarGzReader: diffTarFile,                    // diff.tar.gz reader
		DiffTarLen:      diffTarFileInfo.Size(),         // diff.tar 长度
		TargetImage:     "117503445/layerize-test-base", // target image
		TargetAuth:      auth,                           // target auth
	}
	err = BuildImage(params)
	if err != nil {
		log.Error().Err(err).Msg("BuildImage 执行失败")
		panic(err)
	}

	log.Info().Msg("镜像构建完成")
}

// UploadUpdatedConfigToRegistry 上传更新后的配置到镜像仓库
func UploadUpdatedConfigToRegistry(updatedConfig []byte, registryURL, repository, username, password string) error {
	// 计算更新后配置的SHA256摘要
	configSHA256, err := CalculateDataSHA256(updatedConfig)
	if err != nil {
		log.Error().Err(err).Msg("计算配置SHA256失败")
		return err
	}

	configDigest := "sha256:" + configSHA256

	log.Info().Str("digest", configDigest).Msg("计算配置摘要完成")

	// 上传更新后的配置
	err = UploadConfigToRegistryWithAuth(updatedConfig, configDigest, registryURL, repository, username, password)
	if err != nil {
		log.Error().Err(err).Msg("上传配置到镜像仓库失败")
		return err
	}

	return nil
}
