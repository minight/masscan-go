package ratelimit

import (
	"time"

	"go.uber.org/ratelimit"
)

var (
	ZeroTime = time.Time{}
)

type unlimited struct{}

// NewUnlimited returns a RateLimiter that is not limited.
func NewUnlimited() ratelimit.Limiter {
	return unlimited{}
}

func (unlimited) Take() time.Time {
	return ZeroTime
}
