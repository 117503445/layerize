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

	// 示例：计算 diff.tar.gz 的 SHA256
	sha256sum, err := CalculateFileSHA256("./tmp/diff.tar.gz")
	if err != nil {
		panic(err)
	}

	// 打印SHA256值
	log.Info().Str("sha256", sha256sum).Msg("文件SHA256计算完成")

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
}
