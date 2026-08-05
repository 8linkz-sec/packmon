package parser

import (
	"bufio"
	"io"
)

const maxParserLineSize = 16 * 1024 * 1024

func newLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxParserLineSize)
	return scanner
}
