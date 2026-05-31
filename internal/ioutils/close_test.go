package ioutils

import (
	"errors"
	"testing"
)

type errCloser struct {
	closed bool
}

func (c *errCloser) Close() error {
	c.closed = true
	return errors.New("ignored")
}

type bareCloser struct {
	closed bool
}

func (c *bareCloser) Close() {
	c.closed = true
}

func TestCloseSilentlySupportsErrorAndBareClosers(t *testing.T) {
	t.Parallel()

	withErr := &errCloser{}
	CloseSilently(withErr)
	if !withErr.closed {
		t.Fatal("CloseSilently() did not close error-returning closer")
	}

	bare := &bareCloser{}
	CloseSilently(bare)
	if !bare.closed {
		t.Fatal("CloseSilently() did not close bare closer")
	}

	CloseSilently(struct{}{})
	CloseSilently(nil)
}
