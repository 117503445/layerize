package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// getTokenFromWWWAuth retrieves an authentication token from the WWW-Authenticate header
func getTokenFromWWWAuth(ctx context.Context, wwwAuth, username, password string) (string, error) {
	logger := log.Ctx(ctx)
	
    logger.Info().
		Str("wwwAuth", wwwAuth).
		Str("username", username).
        Str("phase", "auth").
        Int("step", 0).
        Msg("Starting token retrieval process")

	// Add timestamp to help track token requests
    logger.Debug().Time("request_time", time.Now()).Str("phase", "auth").Int("step", 0).Msg("Token request timestamp")

	// Parse WWW-Authenticate header
	// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/hello-world:pull"
	
	if !strings.HasPrefix(wwwAuth, "Bearer ") {
        logger.Error().Str("wwwAuth", wwwAuth).Str("phase", "auth").Int("step", 0).Msg("Unsupported authentication type")
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
        logger.Error().Str("phase", "auth").Int("step", 1).Msg("Realm parameter not found in WWW-Authenticate header")
		return "", fmt.Errorf("realm parameter not found")
	}

    logger.Info().
		Str("realm", realm).
		Str("service", service).
		Str("originalScope", scope).
        Str("phase", "auth").
        Int("step", 1).
        Msg("Parsed authentication parameters")

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
			originalScope := scope
			scope = strings.Replace(scope, ":pull", ":push,pull", 1)
            logger.Info().
				Str("originalScope", originalScope).
				Str("modifiedScope", scope).
                Str("phase", "auth").
                Int("step", 1).
                Msg("Modified scope to include push permissions")
		}
		params = append(params, "scope="+url.QueryEscape(scope))
	}

	if len(params) > 0 {
		authURL += "?" + strings.Join(params, "&")
	}

    logger.Info().Str("authURL", authURL).Str("finalScope", scope).Str("phase", "auth").Int("step", 2).Msg("Requesting authentication token")

	// Request token
	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}

	// Add basic authentication
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	// Add timeout to prevent hanging requests
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

    logger.Debug().Str("phase", "auth").Int("step", 2).Msg("Sending token request to auth server")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
        logger.Error().
			Int("status_code", resp.StatusCode).
			Str("status", resp.Status).
			Str("response_body", string(body)).
			Str("auth_url", authURL).
            Str("phase", "auth").
            Int("step", 2).
            Msg("Authentication request failed")
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

    logger.Info().
		Str("token_prefix", token[:min(len(token), 10)]). // Only log first 10 chars for security
		Int("token_length", len(token)).
		Time("token_obtained_at", time.Now()).
        Str("phase", "auth").
        Int("step", 3).
        Msg("Successfully obtained authentication token")
	return token, nil
}
