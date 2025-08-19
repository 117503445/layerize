package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/internal/config"
	"github.com/117503445/layerize/internal/manifest"
	"github.com/117503445/layerize/internal/registry"
	"github.com/117503445/layerize/internal/types"
	"github.com/117503445/layerize/internal/utils"
	"github.com/rs/zerolog/log"
)

// BuildImageFromMap 从文件映射创建 tar，压缩为 tar.gz，然后构建镜像
func BuildImageFromMap(files map[string][]byte, targetImage string, targetAuth types.Auth, baseImageName string, baseImageAuth types.Auth, baseImageTag string, targetImageTag string) error {
	// 使用 MapToTar 创建 tar 字节数组
	tarData, err := utils.MapToTar(files)
	if err != nil {
		log.Error().Err(err).Msg("创建 tar 数据失败")
		return fmt.Errorf("创建 tar 数据失败: %w", err)
	}

	// 压缩为 tar.gz 格式
	var gzData bytes.Buffer
	gzWriter := gzip.NewWriter(&gzData)
	if _, err := gzWriter.Write(tarData); err != nil {
		log.Error().Err(err).Msg("写入 gzip 数据失败")
		return fmt.Errorf("写入 gzip 数据失败: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		log.Error().Err(err).Msg("关闭 gzip writer 失败")
		return fmt.Errorf("关闭 gzip writer 失败: %w", err)
	}

	// 调用 BuildImage
	params := types.BuildImageParams{
		BaseImageName:   baseImageName,
		BaseImageAuth:   baseImageAuth,
		DiffTarGzReader: bytes.NewReader(gzData.Bytes()),
		DiffTarLen:      int64(gzData.Len()),
		TargetImage:     targetImage,
		TargetAuth:      targetAuth,
		BaseImageTag:    baseImageTag,
		TargetImageTag:  targetImageTag,
	}

	return BuildImage(params)
}

// BuildImage 封装了构建镜像的完整流程
// 参数:
// - params: BuildImageParams 结构体，包含构建镜像所需的所有参数
func BuildImage(params types.BuildImageParams) error {
	goutils.InitZeroLog()

	// 获取 diff.tar 的内容
	diffTarGzData, err := io.ReadAll(params.DiffTarGzReader)
	if err != nil {
		log.Error().Err(err).Msg("读取diffTarGzReader失败")
		return err
	}

	// 解压缩diffTarGzData获取未压缩的数据
	diffTarData, err := utils.DecompressGzipData(diffTarGzData)
	if err != nil {
		log.Error().Err(err).Msg("解压缩diffTar数据失败")
		return err
	}

	// 计算未压缩 diff.tar 的 SHA256 用作 diffID
	diffSha256sum, err := utils.CalculateDataSHA256(diffTarData)
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

	// 直接将压缩的diffTarData写入临时文件
	if _, err := tmpFile.Write(diffTarGzData); err != nil {
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
	sha256sum, err := utils.CalculateFileSHA256(tmpFile.Name())
	if err != nil {
		log.Error().Err(err).Msg("计算压缩文件SHA256失败")
		return err
	}

	// 上传 layer 到目标镜像仓库
	err = registry.UploadLayerToRegistryWithAuth(file, sha256sum, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("UploadLayerToRegistryWithAuth failed")
		return err
	}

	log.Info().Msg("文件上传完成")

	// 声明 updatedConfig 变量
	var updatedConfig []byte

	// 确定基础镜像标签
	baseImageTag := "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// 获取基础镜像配置信息
	baseConfig, err := registry.GetConfigWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("获取config失败")
		return err
	}

	log.Info().Int("configSize", len(baseConfig)).Msg("获取config成功")
	log.Debug().RawJSON("config", baseConfig).Msg("config内容")

	// 调用 UpdateOCIConfig 更新config，使用 diff.tar 的 sha256 作为 diffID
	updatedConfig, err = manifest.UpdateOCIConfig(baseConfig, "sha256:"+diffSha256sum)
	if err != nil {
		log.Error().Err(err).Msg("更新config失败")
		return err
	}

	log.Info().Int("updatedConfigSize", len(updatedConfig)).Msg("更新config成功")
	log.Debug().RawJSON("updatedConfig", updatedConfig).Msg("更新后的config内容")

	// 上传更新后的配置
	err = config.UploadUpdatedConfigToRegistry(updatedConfig, "https://registry.cn-hangzhou.aliyuncs.com", params.TargetImage, params.TargetAuth.Username, params.TargetAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("上传更新后的config失败")
		return err
	}

	log.Info().Msg("上传更新后的config成功")

	// 确定基础镜像标签
	baseImageTag = "latest"
	if params.BaseImageTag != "" {
		baseImageTag = params.BaseImageTag
	}

	// 获取基础镜像manifest示例
	manifestData, contentType, err := registry.GetManifestWithAuth("https://registry.cn-hangzhou.aliyuncs.com", params.BaseImageName, baseImageTag, params.BaseImageAuth.Username, params.BaseImageAuth.Password)
	if err != nil {
		log.Error().Err(err).Msg("获取manifest失败")
		return err
	}

	log.Info().Str("contentType", contentType).Int("manifestSize", len(manifestData)).Msg("获取manifest成功")
	// 如果需要查看manifest内容，可以取消下面的注释
	log.Debug().RawJSON("manifest", manifestData).Msg("manifest内容")

	// 计算更新后配置的SHA256摘要
	configSHA256, err := utils.CalculateDataSHA256(updatedConfig)
	if err != nil {
		log.Error().Err(err).Msg("计算配置SHA256失败")
		return err
	}
	configDigest := "sha256:" + configSHA256

	// 更新 manifest 中的配置引用
	var manifestDataObj map[string]any
	if err := json.Unmarshal(manifestData, &manifestDataObj); err != nil {
		log.Error().Err(err).Msg("解析manifest失败")
		return err
	}

	if configSection, ok := manifestDataObj["config"].(map[string]any); ok {
		configSection["digest"] = configDigest
		// 重新计算配置大小
		configSection["size"] = len(updatedConfig)
	}

	// 重新序列化 manifest
	updatedManifestWithNewConfig, err := json.Marshal(manifestDataObj)
	if err != nil {
		log.Error().Err(err).Msg("序列化更新后的manifest失败")
		return err
	}

	// 调用 updateOCIManifest 更新manifest
	updatedManifest, err := manifest.UpdateOCIManifest(updatedManifestWithNewConfig, "sha256:"+sha256sum, fileSize, "")
	if err != nil {
		log.Error().Err(err).Msg("更新manifest失败")
		return err
	}

	log.Info().Int("updatedManifestSize", len(updatedManifest)).Msg("更新manifest成功")
	log.Debug().RawJSON("updatedManifest", updatedManifest).Msg("更新后的manifest内容")

	// 确定目标镜像标签
	targetImageTag := "latest"
	if params.TargetImageTag != "" {
		targetImageTag = params.TargetImageTag
	}

	// 上传更新后的manifest到目标仓库
	client := registry.NewClient("https://registry.cn-hangzhou.aliyuncs.com", params.TargetAuth.Username, params.TargetAuth.Password)
	err = client.UploadManifest(context.Background(), params.TargetImage, targetImageTag, updatedManifest, contentType)
	if err != nil {
		log.Error().Err(err).Msg("上传更新后的manifest失败")
		return err
	}

	log.Info().Msg("上传更新后的manifest成功")
	return nil
}