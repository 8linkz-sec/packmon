package ioutils

import "io"

// SizeLimitReader wraps r and allows exactly limit bytes. The next read after
// the limit returns errLimit so parsers can consume a valid max-size input.
type SizeLimitReader struct {
	r        io.Reader
	limit    int64
	errLimit func() error
	read     int64
	overflow bool
}

func NewSizeLimitReader(r io.Reader, limit int64, errLimit func() error) *SizeLimitReader {
	return &SizeLimitReader{
		r:        r,
		limit:    limit,
		errLimit: errLimit,
	}
}

func (r *SizeLimitReader) Read(p []byte) (int, error) {
	if r.overflow {
		return 0, r.errLimit()
	}
	remainingWithSentinel := r.limit + 1 - r.read
	if remainingWithSentinel <= 0 {
		r.overflow = true
		return 0, r.errLimit()
	}
	if int64(len(p)) > remainingWithSentinel {
		p = p[:int(remainingWithSentinel)]
	}
	n, err := r.r.Read(p)
	if n == 0 {
		return n, err
	}
	previous := r.read
	r.read += int64(n)
	if r.read > r.limit {
		r.overflow = true
		allowed := int(r.limit - previous)
		if allowed > 0 {
			return allowed, nil
		}
		return 0, r.errLimit()
	}
	return n, err
}
