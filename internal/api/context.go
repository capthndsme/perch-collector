package api

import (
	"context"
	"time"
)

// newTimeoutContext creates a context with a timeout.
func newTimeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
