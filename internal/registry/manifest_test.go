package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetManifestWithAuth_Flow(t *testing.T) {
	t.Parallel()

	// Build an auth server that returns a token
	var authURL string
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer authSrv.Close()
	authURL = authSrv.URL

	manifest := map[string]any{"schemaVersion": 2}
	manifestBytes, _ := json.Marshal(manifest)

	// Registry server: first GET /manifests returns 401 with WWW-Authenticate to authURL; token GET succeeds; final GET with token returns 200
	repo := "library/app"
	reference := "latest"

	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/v2/" { // for client.getAuthURL path in client.go, not used here
            w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authURL+"\",service=\"s\"")
            w.WriteHeader(http.StatusUnauthorized)
			return
		}

        if r.Header.Get("Authorization") == "Bearer t" {
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write(manifestBytes)
			return
		}

        w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authURL+"\",service=\"s\",scope=\"repository:"+repo+":pull\"")
        w.WriteHeader(http.StatusUnauthorized)
	}))
	defer regSrv.Close()

    body, ctype, err := GetManifestWithAuth(context.Background(), regSrv.URL, repo, reference, "user", "pass")
	assert.NoError(t, err)
	assert.NotEmpty(t, body)
    assert.Contains(t, ctype, "manifest")
}
