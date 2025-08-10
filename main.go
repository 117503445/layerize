package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/117503445/goutils"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	goutils.InitZeroLog()

	// 加载 .env 文件
	err := godotenv.Load()
	if err != nil {
		log.Error().Err(err).Msg("加载 .env 文件失败")
		panic(err)
	}

	// 获取 diff.tar.gz 文件信息
	fileInfo, err := os.Stat("./tmp/diff.tar")
	if err != nil {
		log.Error().Err(err).Msg("获取文件信息失败")
		panic(err)
	}
	fileSize := fileInfo.Size()

	// 示例：计算 diff.tar.gz 的 SHA256
	sha256sum, err := CalculateFileSHA256("./tmp/diff.tar.gz")
	if err != nil {
		panic(err)
	}

	// 打印SHA256值和文件大小
	log.Info().Str("sha256", sha256sum).Int64("fileSize", fileSize).Msg("文件SHA256计算完成")

	// 打开文件用于上传
	file, err := os.Open("./tmp/diff.tar.gz")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 从环境变量读取认证信息
	username := os.Getenv("username")
	password := os.Getenv("password")

	// 上传 layer 到阿里云镜像仓库
	err = UploadLayerToRegistryWithAuth(file, sha256sum, "https://registry.cn-hangzhou.aliyuncs.com", "117503445/layerize-test-base", username, password)
	if err != nil {
		log.Panic().Err(err).Msg("UploadLayerToRegistryWithAuth failed")
	}

	log.Info().Msg("文件上传完成")

	// 声明 updatedConfig 变量
	var updatedConfig []byte

	// 获取镜像配置信息
	config, err := GetConfigWithAuth("https://registry.cn-hangzhou.aliyuncs.com", "117503445/layerize-test-base", "latest", username, password)
	if err != nil {
		log.Error().Err(err).Msg("获取config失败")
	} else {
		log.Info().Int("configSize", len(config)).Msg("获取config成功")
		log.Debug().RawJSON("config", config).Msg("config内容")

		// 调用 UpdateOCIConfig 更新config
		updatedConfig, err = UpdateOCIConfig(config, "sha256:"+sha256sum)
		if err != nil {
			log.Error().Err(err).Msg("更新config失败")
		} else {
			log.Info().Int("updatedConfigSize", len(updatedConfig)).Msg("更新config成功")
			log.Debug().RawJSON("updatedConfig", updatedConfig).Msg("更新后的config内容")

			// 上传更新后的配置
			err = UploadUpdatedConfigToRegistry(updatedConfig, "https://registry.cn-hangzhou.aliyuncs.com", "117503445/layerize-test-base", username, password)
			if err != nil {
				log.Error().Err(err).Msg("上传更新后的config失败")
			} else {
				log.Info().Msg("上传更新后的config成功")
			}
		}
	}
	
	// 只有在config更新成功时才继续处理manifest
	if updatedConfig == nil {
		log.Error().Msg("配置未更新成功，跳过manifest处理")
		return
	}

	// 获取镜像manifest示例
	manifest, contentType, err := GetManifestWithAuth("https://registry.cn-hangzhou.aliyuncs.com", "117503445/layerize-test-base", "latest", username, password)
	if err != nil {
		log.Error().Err(err).Msg("获取manifest失败")
	} else {
		log.Info().Str("contentType", contentType).Int("manifestSize", len(manifest)).Msg("获取manifest成功")
		// 如果需要查看manifest内容，可以取消下面的注释
		log.Debug().RawJSON("manifest", manifest).Msg("manifest内容")

		// 计算更新后配置的SHA256摘要
		configSHA256, err := CalculateDataSHA256(updatedConfig)
		if err != nil {
			log.Error().Err(err).Msg("计算配置SHA256失败")
			return
		}
		configDigest := "sha256:" + configSHA256

		// 更新 manifest 中的配置引用
		var manifestData map[string]interface{}
		if err := json.Unmarshal(manifest, &manifestData); err != nil {
			log.Error().Err(err).Msg("解析manifest失败")
			return
		}

		if config, ok := manifestData["config"].(map[string]interface{}); ok {
			config["digest"] = configDigest
			// 重新计算配置大小
			config["size"] = len(updatedConfig)
		}

		// 重新序列化 manifest
		updatedManifestWithNewConfig, err := json.Marshal(manifestData)
		if err != nil {
			log.Error().Err(err).Msg("序列化更新后的manifest失败")
			return
		}

		// 调用 updateOCIManifest 更新manifest
		updatedManifest, err := updateOCIManifest(updatedManifestWithNewConfig, "sha256:"+sha256sum, fileSize, "")
		if err != nil {
			log.Error().Err(err).Msg("更新manifest失败")
		} else {
			log.Info().Int("updatedManifestSize", len(updatedManifest)).Msg("更新manifest成功")
			log.Debug().RawJSON("updatedManifest", updatedManifest).Msg("更新后的manifest内容")

			// 上传更新后的manifest到原始仓库
			client := NewClient("https://registry.cn-hangzhou.aliyuncs.com", username, password)
			// err = client.UploadManifest(context.Background(), "117503445/layerize-test-base", "latest", updatedManifest, contentType)
			// if err != nil {
			// 	log.Error().Err(err).Msg("上传更新后的manifest失败")
			// 	// 记录更多调试信息
			// 	log.Debug().
			// 		Str("contentType", contentType).
			// 		Int("manifestSize", len(updatedManifest)).
			// 		Msg("尝试上传的manifest信息")
			// } else {
			// 	log.Info().Msg("上传更新后的manifest成功")
			// }

			// 上传更新后的manifest到新仓库 117503445/layerize-test-base:08100314
			err = client.UploadManifest(context.Background(), "117503445/layerize-test-base", "08100314", updatedManifest, contentType)
			if err != nil {
				log.Error().Err(err).Msg("上传更新后的manifest到 117503445/layerize-test-base:08100314 失败")
			} else {
				log.Info().Msg("上传更新后的manifest到 117503445/layerize-test-base:08100314 成功")
			}
		}
	}
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
