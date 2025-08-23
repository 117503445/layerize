package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfigWithAuth_Flow(t *testing.T) {
	t.Parallel()

	// Fake manifest with config.digest
	manifest := map[string]any{
		"schemaVersion": 2,
		"config": map[string]any{"digest": "sha256:abc"},
	}
	manifestBytes, _ := json.Marshal(manifest)

	// Auth server
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer authSrv.Close()

	// Registry server behavior:
	// - GET /v2/repo/manifests/tag => 200 returns manifest
	// - GET /v2/repo/blobs/sha256:abc => 401 with WWW-Authenticate to authSrv
	// - GET with Bearer t => 200 returns config content
	repo := "library/app"

    regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
        case r.URL.Path == "/v2/" :
            w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authSrv.URL+"\",service=\"s\"")
            w.WriteHeader(http.StatusUnauthorized)
            return
		case r.URL.Path == "/v2/"+repo+"/manifests/latest":
			_, _ = w.Write(manifestBytes)
			return
        case r.URL.Path == "/v2/"+repo+"/blobs/sha256:abc" && r.Header.Get("Authorization") == "Bearer t":
			_, _ = w.Write([]byte("CONFIG"))
			return
        case r.URL.Path == "/v2/"+repo+"/blobs/sha256:abc":
            w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authSrv.URL+"\",service=\"s\"")
            w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer regSrv.Close()

	cfg, err := GetConfigWithAuth(context.Background(), regSrv.URL, repo, "latest", "user", "pass")
	assert.NoError(t, err)
	assert.Equal(t, []byte("CONFIG"), cfg)
}
