// Package ioutils provides small I/O helpers shared across the codebase.
package ioutils

// closeErrer is satisfied by types whose Close returns an error (e.g. io.Closer).
type closeErrer interface {
	Close() error
}

// closeOnly is satisfied by types whose Close returns nothing (e.g. pgx.Rows).
type closeOnly interface {
	Close()
}

// CloseSilently closes the given value, discarding any error. It accepts
// both io.Closer (Close() error) and types with a bare Close() method.
func CloseSilently(c any) {
	switch closer := c.(type) {
	case closeErrer:
		_ = closer.Close()
	case closeOnly:
		closer.Close()
	}
}
