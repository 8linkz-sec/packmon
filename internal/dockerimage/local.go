package dockerimage

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- production calls this runner with fixed "docker" argv; tests inject alternatives.
	return cmd.Output()
}

type LocalInspector struct {
	Runner CommandRunner
}

func (i LocalInspector) Digests(ctx context.Context, refs []Ref) map[string]string {
	if len(refs) == 0 {
		return nil
	}
	runner := i.Runner
	if runner == nil {
		runner = execRunner{}
	}
	args := []string{"image", "inspect"}
	refByTag := make(map[string]Ref, len(refs))
	for _, ref := range refs {
		if ref.Registry == "" || strings.HasPrefix(ref.Name, "local/") {
			continue
		}
		displayRef := ref.Name + ":" + ref.Reference
		refByTag[displayRef] = ref
		args = append(args, displayRef)
	}
	if len(args) == 2 {
		return nil
	}
	out, err := runner.Run(ctx, "docker", args...)
	if err != nil {
		return nil
	}
	var inspected []struct {
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
		ID          string   `json:"Id"`
	}
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil
	}
	digests := make(map[string]string)
	for _, image := range inspected {
		var matched Ref
		for _, tag := range image.RepoTags {
			if ref, ok := refByTag[normalizeLocalRepoTag(tag)]; ok {
				matched = ref
				break
			}
		}
		if matched.Name == "" {
			continue
		}
		for _, repoDigest := range image.RepoDigests {
			name, digest, ok := strings.Cut(repoDigest, "@")
			if ok && normalizeLocalRepoName(name) == matched.Name {
				digests[matched.Name] = digest
				break
			}
		}
	}
	return digests
}

func normalizeLocalRepoTag(raw string) string {
	ref, ok := ParseRef(raw)
	if !ok {
		return raw
	}
	return ref.Name + ":" + ref.Reference
}

func normalizeLocalRepoName(raw string) string {
	ref, ok := ParseRef(raw + ":latest")
	if !ok {
		return raw
	}
	return ref.Name
}
