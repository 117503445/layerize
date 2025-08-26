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
	return WithRetryAndTokenInvalidator(ctx, operation, config, fn, nil)
}

// WithRetryAndTokenInvalidator executes a function with retry logic and token invalidation callback
func WithRetryAndTokenInvalidator(ctx context.Context, operation string, config RetryConfig, fn func() (*http.Response, error), invalidateToken func()) (*http.Response, error) {
	logger := log.Ctx(ctx)
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt) * config.BaseDelay
            logger.Info().
				Str("operation", operation).
				Int("attempt", attempt).
				Dur("delay", delay).
                Str("phase", "retry").
                Msg("Retrying operation after delay")
			
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		
            logger.Debug().
		Str("operation", operation).
		Int("attempt", attempt).
        Str("phase", "retry").
        Msg("Executing operation")
		
		resp, err := fn()
		if err != nil {
			lastErr = err
                    logger.Warn().
			Err(err).
			Str("operation", operation).
			Int("attempt", attempt).
            Str("phase", "retry").
            Msg("Operation failed with error")
			continue
		}
		
		// Check for authentication errors that should be retried
		if resp.StatusCode == http.StatusUnauthorized {
			if resp.Body != nil {
				resp.Body.Close()
			}
			
			// Invalidate token if callback is provided
			if invalidateToken != nil {
				invalidateToken()
				logger.Info().Str("operation", operation).Int("attempt", attempt).Str("phase", "retry").Msg("Token invalidated due to 401 error")
			}
			
			lastErr = fmt.Errorf("authentication failed: %s", resp.Status)
                    logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("operation", operation).
			Int("attempt", attempt).
            Str("phase", "retry").
            Msg("Operation failed with 401 - will retry")
			continue
		}
		
		// Success or non-retryable failure
            logger.Debug().
		Str("operation", operation).
		Int("attempt", attempt).
		Int("status_code", resp.StatusCode).
        Str("phase", "retry").
        Msg("Operation completed")
		return resp, nil
	}
	
    logger.Error().
		Err(lastErr).
		Str("operation", operation).
		Int("max_attempts", config.MaxRetries + 1).
        Str("phase", "retry").
        Msg("Operation failed after all retry attempts")
	
	return nil, fmt.Errorf("operation %s failed after %d attempts: %w", operation, config.MaxRetries+1, lastErr)
}