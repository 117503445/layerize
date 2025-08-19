package validator

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// ValidateBuiltImage validates if the built image is correct
func ValidateBuiltImage(content string) error {
	// Add podman test
	// podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run -it --rm --entrypoint sh registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357
	// Require new.txt to exist with content as content. old.txt should not exist.
	cmd := exec.Command("sh", "-c", "podman pull registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 && podman run --rm --entrypoint cat registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357 /new.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(output)).Msg("Failed to execute podman pull and cat new.txt")
		return fmt.Errorf("failed to execute podman pull and cat new.txt: %w", err)
	}

	// Only get the last line as file content, ignoring possible container ID and other information
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	lastLine := lines[len(lines)-1]

	if lastLine != content {
		log.Error().Str("expected", content).Str("actual", lastLine).Msg("new.txt content mismatch")
		return fmt.Errorf("new.txt content mismatch: expected %s, actual %s", content, lastLine)
	}

	log.Info().Str("content", content).Msg("Successfully validated new.txt content")

	// Check if old.txt does not exist
	cmd = exec.Command("sh", "-c", "podman run --rm --entrypoint ls registry.cn-hangzhou.aliyuncs.com/117503445/layerize-test-base:08182357")
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(output)).Msg("Failed to execute podman run ls")
		return fmt.Errorf("failed to execute podman run ls: %w", err)
	}

	if strings.Contains(string(output), "old.txt") {
		log.Error().Str("output", string(output)).Msg("old.txt should not exist but was found")
		return fmt.Errorf("old.txt should not exist but was found")
	}

	log.Info().Msg("Successfully validated old.txt does not exist")
	return nil
}