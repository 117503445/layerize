package registry

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWithRetry_SucceedsAfterUnauthorized(t *testing.T) {
	t.Parallel()

	calls := 0
	resp, err := WithRetry(context.Background(), "op", RetryConfig{MaxRetries: 3, BaseDelay: 1 * time.Millisecond}, func() (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestWithRetry_FailsAfterMaxRetries(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := WithRetry(context.Background(), "op", RetryConfig{MaxRetries: 2, BaseDelay: 1 * time.Millisecond}, func() (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
	})
	assert.Error(t, err)
	assert.Equal(t, 3, calls)
}

func TestWithRetry_ErrorReturned(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := WithRetry(context.Background(), "op", RetryConfig{MaxRetries: 1, BaseDelay: 1 * time.Millisecond}, func() (*http.Response, error) {
		calls++
		return nil, errors.New("network error")
	})
	assert.Error(t, err)
	assert.Equal(t, 2, calls)
}
