package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

// getTokenFromWWWAuth retrieves an authentication token from the WWW-Authenticate header
func getTokenFromWWWAuth(wwwAuth, username, password string) (string, error) {
	// Parse WWW-Authenticate header
	// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
	
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
		return "", fmt.Errorf("unsupported auth type: %s", wwwAuth)
	}

	// Extract parameters
	params := strings.Split(wwwAuth[7:], ",")
	var realm, service, scope string

	for _, param := range params {
		param = strings.TrimSpace(param)
		if strings.HasPrefix(param, "realm=") {
			realm = strings.Trim(param[6:], "\"")
		} else if strings.HasPrefix(param, "service=") {
			service = strings.Trim(param[8:], "\"")
		} else if strings.HasPrefix(param, "scope=") {
			scope = strings.Trim(param[6:], "\"")
		}
	}

	if realm == "" {
		return "", fmt.Errorf("realm parameter not found")
	}

	// Build auth URL
	authURL := realm
	params = []string{}
	if service != "" {
		params = append(params, "service="+url.QueryEscape(service))
	}
	// For upload operations, we need to modify scope to include push permissions
	if scope != "" {
		// If original scope only contains pull, we need to add push permissions
		if strings.Contains(scope, ":pull") && !strings.Contains(scope, ":push") {
			scope = strings.Replace(scope, ":pull", ":push,pull", 1)
		}
		params = append(params, "scope="+url.QueryEscape(scope))
	}

	if len(params) > 0 {
		authURL += "?" + strings.Join(params, "&")
	}

	log.Info().Str("authURL", authURL).Str("scope", scope).Msg("Requesting authentication token")

	// Request token
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	// Add basic authentication
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication failed: %s, response: %s", resp.Status, string(body))
	}

	// Parse token response
	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	token := tokenResp.Token
	if token == "" {
		token = tokenResp.AccessToken
	}

	if token == "" {
		return "", fmt.Errorf("no valid token received")
	}

	log.Info().Msg("Successfully obtained authentication token")
	return token, nil
}