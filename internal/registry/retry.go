package registry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
}

// DefaultRetryConfig returns a reasonable default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 3,
		BaseDelay:  500 * time.Millisecond,
	}
}

// WithRetry executes a function with retry logic for authentication failures
func WithRetry(ctx context.Context, operation string, config RetryConfig, fn func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt) * config.BaseDelay
			log.Info().
				Str("operation", operation).
				Int("attempt", attempt).
				Dur("delay", delay).
				Msg("Retrying operation after delay")
			
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		
		log.Debug().
			Str("operation", operation).
			Int("attempt", attempt).
			Msg("Executing operation")
		
		resp, err := fn()
		if err != nil {
			lastErr = err
			log.Warn().
				Err(err).
				Str("operation", operation).
				Int("attempt", attempt).
				Msg("Operation failed with error")
			continue
		}
		
		// Check for authentication errors that should be retried
		if resp.StatusCode == http.StatusUnauthorized {
			if resp.Body != nil {
				resp.Body.Close()
			}
			lastErr = fmt.Errorf("authentication failed: %s", resp.Status)
			log.Warn().
				Int("status_code", resp.StatusCode).
				Str("operation", operation).
				Int("attempt", attempt).
				Msg("Operation failed with 401 - will retry")
			continue
		}
		
		// Success or non-retryable failure
		log.Debug().
			Str("operation", operation).
			Int("attempt", attempt).
			Int("status_code", resp.StatusCode).
			Msg("Operation completed")
		return resp, nil
	}
	
	log.Error().
		Err(lastErr).
		Str("operation", operation).
		Int("max_attempts", config.MaxRetries + 1).
		Msg("Operation failed after all retry attempts")
	
	return nil, fmt.Errorf("operation %s failed after %d attempts: %w", operation, config.MaxRetries+1, lastErr)
}