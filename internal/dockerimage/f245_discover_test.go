package dockerimage

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestF245DiscoverFilesWalkerErrorControlFlow(t *testing.T) {
	root := t.TempDir()
	originalWalkDir := walkDockerInventoryDir
	t.Cleanup(func() { walkDockerInventoryDir = originalWalkDir })

	t.Run("root error with nil entry is reported and continued", func(t *testing.T) {
		walkDockerInventoryDir = func(walkRoot string, fn fs.WalkDirFunc) error {
			return fn(walkRoot, nil, &fs.PathError{Op: "open", Path: walkRoot, Err: fs.ErrPermission})
		}

		files, warnings, err := DiscoverFilesWithWarnings(root, 2)
		if err != nil || files != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "permission") {
			t.Fatalf("DiscoverFilesWithWarnings(root error) = (%+v, %+v, %v)", files, warnings, err)
		}
		if !strings.HasPrefix(warnings[0], "docker-inventory-file: ") {
			t.Fatalf("root warning = %q, want bounded Docker inventory placeholder", warnings[0])
		}
		for _, leaked := range []string{root, filepath.ToSlash(root)} {
			if strings.Contains(warnings[0], leaked) {
				t.Fatalf("root warning leaks absolute scan root %q: %q", leaked, warnings[0])
			}
		}
	})

	t.Run("nested errors skip directories and continue files before final error", func(t *testing.T) {
		finalErr := errors.New("injected final walker error")
		walkDockerInventoryDir = func(walkRoot string, fn fs.WalkDirFunc) error {
			if err := fn(walkRoot, fakeDockerDirEntry{name: filepath.Base(walkRoot), dir: true}, nil); err != nil {
				return err
			}
			privateDir := filepath.Join(walkRoot, "private")
			if err := fn(privateDir, fakeDockerDirEntry{name: "private", dir: true}, &fs.PathError{
				Op: "readdir", Path: privateDir, Err: fs.ErrPermission,
			}); !errors.Is(err, fs.SkipDir) {
				return errors.New("directory walk error did not request SkipDir")
			}
			goneFile := filepath.Join(walkRoot, "gone", "Dockerfile")
			if err := fn(goneFile, fakeDockerDirEntry{name: "Dockerfile"}, errors.New("file vanished")); err != nil {
				return err
			}
			return finalErr
		}

		files, warnings, err := DiscoverFilesWithWarnings(root, 2)
		if files != nil || !errors.Is(err, finalErr) || len(warnings) != 2 {
			t.Fatalf("DiscoverFilesWithWarnings(nested/final errors) = (%+v, %+v, %v)", files, warnings, err)
		}
		if !strings.Contains(warnings[0], "private") || !strings.Contains(warnings[0], "permission") ||
			!strings.Contains(warnings[1], "gone/Dockerfile") || !strings.Contains(warnings[1], "file vanished") {
			t.Fatalf("nested warnings = %+v, want relative directory and file diagnostics", warnings)
		}
		for _, warning := range warnings {
			if strings.Contains(warning, filepath.ToSlash(root)) {
				t.Fatalf("nested warning leaks absolute root %q: %q", root, warning)
			}
		}
	})
}

func TestF245DockerInventoryRelDisplayUsesPlaceholderForFilesystemRoot(t *testing.T) {
	volumeRoot := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	if got := dockerInventoryRelDisplay(volumeRoot); got != "docker-inventory-file" {
		t.Fatalf("dockerInventoryRelDisplay(%q) = %q, want placeholder", volumeRoot, got)
	}
}
