package main

import (
	"os"

	"github.com/117503445/goutils"
	"github.com/117503445/layerize/internal/builder"
	"github.com/117503445/layerize/internal/types"
	"github.com/117503445/layerize/internal/validator"
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

	// 从环境变量读取认证信息
	username := os.Getenv("username")
	password := os.Getenv("password")
	auth := types.Auth{Username: username, Password: password}

	content := goutils.TimeStrMilliSec()

	// 创建文件映射，模拟 tmp/diff.tar 中的内容
	files := map[string][]byte{
		"new.txt":     []byte(content),
		".wh.old.txt": []byte(""),
	}

	// 调用 buildImageFromMap 函数执行构建操作
	err = builder.BuildImageFromMap(
		files,
		"117503445/layerize-test-base", // target image
		auth,                           // target auth
		"117503445/layerize-test-base", // base image name
		auth,                           // base image auth
		"latest",                       // base image tag
		"08182357",                     // target image tag
	)
	if err != nil {
		log.Error().Err(err).Msg("buildImageFromMap 执行失败")
		panic(err)
	}

	log.Info().Msg("镜像构建完成")

	// 验证构建的镜像
	err = validator.ValidateBuiltImage(content)
	if err != nil {
		log.Error().Err(err).Msg("镜像验证失败")
		panic(err)
	}

	log.Info().Msg("镜像验证完成")
}