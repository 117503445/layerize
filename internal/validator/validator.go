package validator

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// ValidateBuiltImage validates if the built image is correct
func ValidateBuiltImage(ctx context.Context, content string) error {
	logger := log.Ctx(ctx)
	
    // Add podman test
    logger.Info().Str("phase", "validate").Int("step", 0).Msg("开始通过 podman 验证构建结果")
	// podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run -it --rm --entrypoint sh registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357
	// Require new.txt to exist with content as content. old.txt should not exist.
	cmd := exec.Command("sh", "-c", "podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run --rm --entrypoint cat registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 /new.txt")
	output, err := cmd.CombinedOutput()
    if err != nil {
        logger.Error().Err(err).Str("phase", "validate").Int("step", 1).Str("output", string(output)).Msg("Failed to execute podman pull and cat new.txt")
		return fmt.Errorf("failed to execute podman pull and cat new.txt: %w", err)
	}
    logger.Info().Str("phase", "validate").Int("step", 1).Msg("已拉取镜像并读取 /new.txt")

	// Only get the last line as file content, ignoring possible container ID and other information
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	lastLine := lines[len(lines)-1]

    if lastLine != content {
        logger.Error().Str("phase", "validate").Int("step", 2).Str("expected", content).Str("actual", lastLine).Msg("new.txt content mismatch")
		return fmt.Errorf("new.txt content mismatch: expected %s, actual %s", content, lastLine)
	}

    logger.Info().Str("phase", "validate").Int("step", 2).Str("content", content).Msg("已验证 /new.txt 内容正确")

	// Check if old.txt does not exist
	cmd = exec.Command("sh", "-c", "podman run --rm --entrypoint ls registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357")
    output, err = cmd.CombinedOutput()
    if err != nil {
        logger.Error().Err(err).Str("phase", "validate").Int("step", 3).Str("output", string(output)).Msg("Failed to execute podman run ls")
		return fmt.Errorf("failed to execute podman run ls: %w", err)
	}

    if strings.Contains(string(output), "old.txt") {
        logger.Error().Str("phase", "validate").Int("step", 4).Str("output", string(output)).Msg("old.txt should not exist but was found")
		return fmt.Errorf("old.txt should not exist but was found")
	}

    logger.Info().Str("phase", "validate").Int("step", 4).Msg("已验证 /old.txt 不存在")
	return nil
}