package main

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const maxGitCommandOutputBytes = 4 << 20

var (
	errGitCommandOutputTooLarge = errors.New("git command output exceeds maximum size")
	gitCommandOutput            = defaultGitCommandOutput
	gitMetadataTimeout          = 2 * time.Second
)

type gitOutputBuffer struct {
	data      []byte
	oversized bool
}

func (b *gitOutputBuffer) Write(p []byte) (int, error) {
	remaining := maxGitCommandOutputBytes - len(b.data)
	if remaining > 0 {
		if len(p) <= remaining {
			b.data = append(b.data, p...)
		} else {
			b.data = append(b.data, p[:remaining]...)
			b.oversized = true
		}
	} else if len(p) > 0 {
		b.oversized = true
	}
	return len(p), nil
}

func (b *gitOutputBuffer) Bytes() ([]byte, error) {
	out := append([]byte(nil), b.data...)
	if b.oversized {
		return out, errGitCommandOutputTooLarge
	}
	return out, nil
}

func defaultGitCommandOutput(ctx context.Context, args ...string) ([]byte, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- command is fixed to git; arguments are internally constructed and no shell is used.
	cmd.WaitDelay = 2 * time.Second

	var stdout gitOutputBuffer
	var stderr gitOutputBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if _, outputErr := stderr.Bytes(); outputErr != nil {
			return nil, outputErr
		}
		return nil, err
	}
	out, err := stdout.Bytes()
	if err != nil {
		return nil, err
	}
	if _, err := stderr.Bytes(); err != nil {
		return nil, err
	}
	return out, nil
}
