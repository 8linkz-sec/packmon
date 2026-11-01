package main

import (
	"fmt"
	"math"
	"time"
)

// defaultScanTimeoutSeconds is the scan --timeout default.
const defaultScanTimeoutSeconds = 30

// maxTimeoutSeconds is the largest whole-second timeout that still fits a
// time.Duration; larger values would overflow into a negative, immediately
// expired deadline.
const maxTimeoutSeconds = math.MaxInt64 / int64(time.Second)

// validateTimeoutUpperBound rejects a whole-second timeout that does not fit a
// time.Duration. name identifies the source (flag, config key or environment
// variable) in the error.
func validateTimeoutUpperBound(name string, seconds int) error {
	if int64(seconds) > maxTimeoutSeconds {
		return fmt.Errorf("%s must be at most %d seconds", name, maxTimeoutSeconds)
	}
	return nil
}

// timeoutSecondsDuration converts a whole-second timeout to a time.Duration,
// rejecting non-positive values and values that would overflow. Every CLI
// timeout source (--timeout, config timeout, repos[].timeout, PACKMON_TIMEOUT)
// goes through this bound before it is multiplied by time.Second.
func timeoutSecondsDuration(name string, seconds int) (time.Duration, error) {
	if seconds <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	if err := validateTimeoutUpperBound(name, seconds); err != nil {
		return 0, err
	}
	return time.Duration(seconds) * time.Second, nil
}

// boundedTimeoutDuration converts an already resolved whole-second timeout for
// consumers that cannot return an error. A non-positive or unrepresentable
// value yields fallback instead of a wrapped, already expired (or near-zero)
// deadline; resolveScanSettings rejects such values before they get here.
func boundedTimeoutDuration(seconds int, fallback time.Duration) time.Duration {
	d, err := timeoutSecondsDuration("timeout", seconds)
	if err != nil {
		return fallback
	}
	return d
}
