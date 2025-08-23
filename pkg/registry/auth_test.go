package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTokenFromWWWAuth_Success(t *testing.T) {
	t.Parallel()

	// Fake auth server returning a token
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok123"})
	}))
	defer srv.Close()

	wwwAuth := "Bearer realm=\"" + srv.URL + "\",service=\"s\",scope=\"repository:repo:pull\""
	token, err := getTokenFromWWWAuth(context.Background(), wwwAuth, "u", "p")
	assert.NoError(t, err)
	assert.Equal(t, "tok123", token)
}

func TestGetTokenFromWWWAuth_Errors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		www    string
	}{
		{"badtype", "Basic abc"},
		{"missing realm", "Bearer service=\"s\""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := getTokenFromWWWAuth(context.Background(), tc.www, "u", "p")
			assert.Error(t, err)
		})
	}
}
