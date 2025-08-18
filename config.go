package main

import (
	"github.com/rs/zerolog/log"
)

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