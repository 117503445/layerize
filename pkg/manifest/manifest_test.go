package manifest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateDockerManifestV2(t *testing.T) {
	t.Parallel()

	orig := DockerManifestV2{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifest,
		Config:        ManifestConfig{MediaType: "application/vnd.docker.container.image.v1+json", Size: 123, Digest: "sha256:cfg"},
		Layers:        []ManifestLayer{{MediaType: MediaTypeDockerLayer, Size: 1, Digest: "sha256:old"}},
	}
	b, _ := json.Marshal(orig)

	newB, err := UpdateDockerManifestV2(context.Background(), b, "sha256:new", 42, "")
	assert.NoError(t, err)

	var got DockerManifestV2
	_ = json.Unmarshal(newB, &got)
	assert.Equal(t, 2, got.SchemaVersion)
	assert.Len(t, got.Layers, 2)
	assert.Equal(t, "sha256:new", got.Layers[1].Digest)
	assert.Equal(t, int64(42), got.Layers[1].Size)
	assert.Equal(t, MediaTypeDockerLayer, got.Layers[1].MediaType)
}

func TestUpdateOCIManifest_DefaultsMediaType(t *testing.T) {
	t.Parallel()
	orig := OCIManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        ManifestConfig{MediaType: "application/vnd.oci.image.config.v1+json", Size: 200, Digest: "sha256:cfg"},
		Layers:        []ManifestLayer{},
	}
	b, _ := json.Marshal(orig)

	newB, err := UpdateOCIManifest(context.Background(), b, "sha256:new", 7, "")
	assert.NoError(t, err)

	var got OCIManifest
	_ = json.Unmarshal(newB, &got)
	assert.Len(t, got.Layers, 1)
	assert.Equal(t, MediaTypeOCILayer, got.Layers[0].MediaType)
}

func TestUpdateManifest_DispatchAndError(t *testing.T) {
	t.Parallel()
	t.Run("docker", func(t *testing.T) {
		m := DockerManifestV2{SchemaVersion: 2, MediaType: MediaTypeDockerManifest}
		b, _ := json.Marshal(m)
		_, mt, err := UpdateManifest(context.Background(), b, "sha256:x", 1, "")
		assert.NoError(t, err)
		assert.Equal(t, MediaTypeDockerManifest, mt)
	})

	t.Run("oci", func(t *testing.T) {
		m := OCIManifest{SchemaVersion: 2, MediaType: MediaTypeOCIManifest}
		b, _ := json.Marshal(m)
		_, mt, err := UpdateManifest(context.Background(), b, "sha256:x", 1, "")
		assert.NoError(t, err)
		assert.Equal(t, MediaTypeOCIManifest, mt)
	})

	t.Run("unsupported", func(t *testing.T) {
		generic := map[string]any{"mediaType": "application/unknown"}
		b, _ := json.Marshal(generic)
		_, _, err := UpdateManifest(context.Background(), b, "sha256:x", 1, "")
		assert.Error(t, err)
	})
}

func TestUpdateOCIConfig_AddsDiffIDAndCreatesRootfs(t *testing.T) {
	t.Parallel()

	baseConfig := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
	}
	b, _ := json.Marshal(baseConfig)

	updated, err := UpdateOCIConfig(context.Background(), b, "sha256:abc")
	assert.NoError(t, err)

	var parsed map[string]any
	_ = json.Unmarshal(updated, &parsed)
	rootfs := parsed["rootfs"].(map[string]any)
	diffIDs := rootfs["diff_ids"].([]any)
	assert.Equal(t, "layers", rootfs["type"])
	assert.Equal(t, "sha256:abc", diffIDs[0])
}

func TestUpdateOCIConfig_AppendsToExistingDiffIDs(t *testing.T) {
	t.Parallel()

	baseConfig := map[string]any{
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []any{"sha256:old"},
		},
	}
	b, _ := json.Marshal(baseConfig)

	updated, err := UpdateOCIConfig(context.Background(), b, "sha256:new")
	assert.NoError(t, err)

	var parsed map[string]any
	_ = json.Unmarshal(updated, &parsed)
	diffIDs := parsed["rootfs"].(map[string]any)["diff_ids"].([]any)
	assert.Equal(t, []any{"sha256:old", "sha256:new"}, diffIDs)
}
