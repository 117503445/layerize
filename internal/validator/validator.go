package validator

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// ValidateBuiltImage 验证构建的镜像是否正确
func ValidateBuiltImage(content string) error {
	// 添加 podman 测试
	// podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run -it --rm --entrypoint sh registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357
	// 要求存在 new.txt，且内容是 content。old.txt 需要不存在
	cmd := exec.Command("sh", "-c", "podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run --rm --entrypoint cat registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 /new.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(output)).Msg("执行 podman pull 和 cat new.txt 失败")
		return fmt.Errorf("执行 podman pull 和 cat new.txt 失败: %w", err)
	}

	// 只获取最后一行作为文件内容，忽略可能的容器ID等信息
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	lastLine := lines[len(lines)-1]

	if lastLine != content {
		log.Error().Str("expected", content).Str("actual", lastLine).Msg("new.txt 内容不匹配")
		return fmt.Errorf("new.txt 内容不匹配: 期望 %s, 实际 %s", content, lastLine)
	}

	log.Info().Str("content", content).Msg("验证 new.txt 内容成功")

	// 检查 old.txt 是否不存在
	cmd = exec.Command("sh", "-c", "podman run --rm --entrypoint ls registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(output)).Msg("执行 podman run ls 失败")
		return fmt.Errorf("执行 podman run ls 失败: %w", err)
	}

	if strings.Contains(string(output), "old.txt") {
		log.Error().Str("output", string(output)).Msg("old.txt 应该不存在但被找到了")
		return fmt.Errorf("old.txt 应该不存在但被找到了")
	}

	log.Info().Msg("验证 old.txt 不存在成功")
	return nil
}