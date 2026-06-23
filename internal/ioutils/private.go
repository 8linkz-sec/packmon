package ioutils

import "os"

// OpenPrivateFile opens path for overwrite and ensures the resulting file is
// owner-readable/writable even when an existing broader-mode file is reused.
func OpenPrivateFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- callers pass intentional local output paths.
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		CloseSilently(file)
		return nil, err
	}
	return file, nil
}
