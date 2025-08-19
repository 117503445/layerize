package config

import (
	"crypto/sha256"
	"fmt"

	"github.com/117503445/layerize/internal/registry"
	"github.com/rs/zerolog/log"
)

// UploadUpdatedConfigToRegistry 上传更新后的配置到镜像仓库
func UploadUpdatedConfigToRegistry(updatedConfig []byte, registryURL, repository, username, password string) error {
	// 计算配置的 SHA256 摘要
	hash := sha256.Sum256(updatedConfig)
	configDigest := fmt.Sprintf("sha256:%x", hash)

	log.Info().Str("configDigest", configDigest).Int("configSize", len(updatedConfig)).Msg("开始上传更新后的配置")

	// 使用 registry 包的函数上传配置
	err := registry.UploadConfigToRegistryWithAuth(updatedConfig, configDigest, registryURL, repository, username, password)
	if err != nil {
		log.Error().Err(err).Msg("上传配置失败")
		return fmt.Errorf("上传配置失败: %w", err)
	}

	log.Info().Msg("配置上传成功")
	return nil
}