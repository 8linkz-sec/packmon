package feed

import (
	"fmt"
	"io"
	"os"
)

const MaxGitAdvisoryJSONSize = 10 << 20

func ReadRootFileLimited(root *os.Root, name string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxGitAdvisoryJSONSize
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Mode().IsRegular() && info.Size() > maxBytes {
		return nil, advisoryJSONSizeLimitError(maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, advisoryJSONSizeLimitError(maxBytes)
	}
	return data, nil
}

func advisoryJSONSizeLimitError(maxBytes int64) error {
	return fmt.Errorf("advisory JSON exceeds maximum advisory JSON size of %d bytes", maxBytes)
}
