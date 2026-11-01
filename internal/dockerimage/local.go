package dockerimage

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

type ImageInspectRunner interface {
	Inspect(ctx context.Context, refs []string) ([]byte, error)
}

type execInspectRunner struct{}

func (execInspectRunner) Inspect(ctx context.Context, refs []string) ([]byte, error) {
	args := make([]string, 0, len(refs)+3)
	args = append(args, "image", "inspect")
	if len(refs) > 0 {
		args = append(args, "--")
	}
	args = append(args, refs...)
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed docker executable and subcommand; refs are argv-only after an option terminator, no shell is used.
	cmd.WaitDelay = 2 * time.Second
	return cmd.Output()
}

type LocalInspector struct {
	Runner ImageInspectRunner
}

// Digests returns the local repo digest of each installed tag in refs, keyed
// by LocalDigestKey. Missing images, a missing docker CLI, or unparseable
// output leave the affected references out.
func (i LocalInspector) Digests(ctx context.Context, refs []Ref) map[string]string {
	if len(refs) == 0 {
		return nil
	}
	runner := i.Runner
	if runner == nil {
		runner = execInspectRunner{}
	}
	inspectRefs := make([]string, 0, len(refs))
	refByTag := make(map[string]Ref, len(refs))
	for _, ref := range refs {
		if ref.Registry == "" || strings.HasPrefix(ref.Name, "local/") {
			continue
		}
		displayRef := LocalDigestKey(ref)
		refByTag[displayRef] = ref
		inspectRefs = append(inspectRefs, displayRef)
	}
	if len(inspectRefs) == 0 {
		return nil
	}
	out, err := runner.Inspect(ctx, inspectRefs)
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
		// One image can carry several requested tags; each gets the digest.
		for _, tag := range image.RepoTags {
			key := normalizeLocalRepoTag(tag)
			matched, ok := refByTag[key]
			if !ok {
				continue
			}
			for _, repoDigest := range image.RepoDigests {
				name, digest, ok := strings.Cut(repoDigest, "@")
				if ok && normalizeLocalRepoName(name) == matched.Name {
					digests[key] = digest
					break
				}
			}
		}
	}
	return digests
}

// LocalDigestKey is the key of a reference in the map Digests returns: the
// repository plus its tag. Several tags of one repository are separate local
// images with their own digests, so the repository name alone is not unique.
func LocalDigestKey(ref Ref) string {
	return ref.Name + ":" + ref.Reference
}

func normalizeLocalRepoTag(raw string) string {
	ref, ok := ParseRef(raw)
	if !ok {
		return raw
	}
	return LocalDigestKey(ref)
}

func normalizeLocalRepoName(raw string) string {
	ref, ok := ParseRef(raw + ":latest")
	if !ok {
		return raw
	}
	return ref.Name
}
