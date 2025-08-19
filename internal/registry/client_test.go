package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToken_IsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()
    cases := []struct {
		name      string
		token     Token
		expired   bool
	}{
        {"no expiry uses default", Token{ExpiresIn: 0, IssuedAt: now.Add(-58 * time.Minute)}, false},
		{"expired with buffer", Token{ExpiresIn: 120, IssuedAt: now.Add(-3 * time.Minute)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expired, tc.token.IsExpired(context.Background()))
		})
	}
}

func TestClient_getAuthURL(t *testing.T) {
	t.Parallel()

	// Registry that returns 401 with proper WWW-Authenticate
    authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte(`{"access_token":"t"}`))
    }))
	defer authSrv.Close()

    regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Respond to /v2/ with 401 and header, which client.getAuthURL requests
        if r.URL.Path == "/v2/" {
            w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authSrv.URL+"\",service=\"svc\"")
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusNotFound)
    }))
	defer regSrv.Close()

	c := NewClient(regSrv.URL, "u", "p")
	url, err := c.getAuthURL(context.Background(), "repository:repo:pull")
	assert.NoError(t, err)
	assert.Contains(t, url, authSrv.URL)
	assert.Contains(t, url, "service=svc")
	assert.Contains(t, url, "scope=")
}

func TestClient_getAuthorizationHeader_CachesToken(t *testing.T) {
	t.Parallel()

	// Auth endpoint that always returns a token
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Token{AccessToken: "t", ExpiresIn: 3600, IssuedAt: time.Now()})
	}))
	defer authSrv.Close()

    regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/v2/" {
            w.Header().Set("WWW-Authenticate", "Bearer realm=\""+authSrv.URL+"\",service=\"svc\"")
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusNotFound)
    }))
	defer regSrv.Close()

    c := NewClient(regSrv.URL, "u", "p")
    h1, err := c.getAuthorizationHeader(context.Background(), "repository:repo:pull")
	assert.NoError(t, err)
    h2, err := c.getAuthorizationHeader(context.Background(), "repository:repo:pull")
	assert.NoError(t, err)
	assert.Equal(t, h1, h2)
}
