package main

type closeErrer interface {
	Close() error
}

type closeOnly interface {
	Close()
}

func closeSilently(c any) {
	switch closer := c.(type) {
	case closeErrer:
		_ = closer.Close()
	case closeOnly:
		closer.Close()
	}
}
