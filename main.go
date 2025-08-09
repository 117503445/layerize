package main

import (
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
	fileInfo, err := os.Stat("./tmp/diff.tar.gz")
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
	
	// 获取镜像manifest示例
	manifest, contentType, err := GetManifestWithAuth("https://registry.cn-hangzhou.aliyuncs.com", "117503445/layerize-test-base", "latest", username, password)
	if err != nil {
		log.Error().Err(err).Msg("获取manifest失败")
	} else {
		log.Info().Str("contentType", contentType).Int("manifestSize", len(manifest)).Msg("获取manifest成功")
		// 如果需要查看manifest内容，可以取消下面的注释
		log.Debug().RawJSON("manifest", manifest).Msg("manifest内容")
		
		// 调用 updateOCIManifest 更新manifest
		updatedManifest, err := updateOCIManifest(manifest, "sha256:"+sha256sum, fileSize, "")
		if err != nil {
			log.Error().Err(err).Msg("更新manifest失败")
		} else {
			log.Info().Int("updatedManifestSize", len(updatedManifest)).Msg("更新manifest成功")
			log.Debug().RawJSON("updatedManifest", updatedManifest).Msg("更新后的manifest内容")
		}
	}
}