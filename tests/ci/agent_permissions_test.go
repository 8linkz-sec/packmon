package ci

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentGuideWarnsIgnoredSecretsAreNotSafeForAgentContext(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	agentsData, err := os.ReadFile(filepath.Join(root, "AGENTS.md")) //nolint:gosec // static repository documentation path.
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	gitignoreData, err := os.ReadFile(filepath.Join(root, ".gitignore")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}

	agents := string(agentsData)
	for _, want := range []string{
		"Do not read, summarize, paste, or otherwise ingest ignored secret files",
		".env",
		".env.*",
		"ignored files are still visible to local agents",
	} {
		if !strings.Contains(agents, want) {
			t.Fatalf("AGENTS.md missing ignored-secret agent warning %q", want)
		}
	}
	for _, want := range []string{".env", ".env.*"} {
		if !ignorePatternContains(string(gitignoreData), want) {
			t.Fatalf(".gitignore missing ignored secret pattern %q", want)
		}
	}
}

func ignorePatternContains(text, pattern string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == pattern {
			return true
		}
	}
	return false
}

func TestLocalClaudeSettingsDoNotGrantBroadRepoReadOverIgnoredSecrets(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".claude", "settings.json")
	data, err := os.ReadFile(path) //nolint:gosec // local permissions fixture; test never reads secret files.
	if errors.Is(err, os.ErrNotExist) {
		t.Skip(".claude/settings.json is local and not present")
	}
	if err != nil {
		t.Fatalf("read .claude/settings.json: %v", err)
	}

	var settings struct {
		Permissions struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse .claude/settings.json: %v", err)
	}

	for _, rule := range settings.Permissions.Allow {
		if strings.TrimSpace(rule) == "Read(//e/Github/packmon/**)" {
			t.Fatal(".claude/settings.json still grants broad Read(//e/Github/packmon/**)")
		}
	}
	denyText := strings.Join(settings.Permissions.Deny, "\n")
	for _, want := range []string{".env", ".env.*"} {
		if !strings.Contains(denyText, want) {
			t.Fatalf(".claude/settings.json deny rules missing %q", want)
		}
	}
}

func TestLocalClaudeSettingsDoNotEmbedSecretsOrRiskyShellAllowlists(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"settings.json", "settings.local.json"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("..", "..", ".claude", name)
			settings, ok := readLocalClaudeSettings(t, path)
			if !ok {
				return
			}

			for _, rule := range settings.Permissions.Allow {
				lower := strings.ToLower(rule)
				if strings.Contains(lower, "authorization: bearer") {
					t.Fatalf("%s embeds an Authorization bearer token in an allow rule", name)
				}
				if strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") {
					t.Fatalf("%s embeds an API-key-looking value in an allow rule", name)
				}
				for _, disallowed := range []string{
					"Bash(mv:*)",
					"Bash(go run:*)",
					"Bash(go clean:*)",
					"Bash(docker volume:*)",
					"Bash(grep:*)",
				} {
					if strings.TrimSpace(rule) == disallowed {
						t.Fatalf("%s still grants risky shell allow rule %q", name, disallowed)
					}
				}
			}

			denyText := strings.Join(settings.Permissions.Deny, "\n")
			for _, want := range []string{
				"Bash(go run:*)",
				"Bash(go clean:*)",
				"Bash(docker volume:*)",
				"Authorization: Bearer",
			} {
				if !strings.Contains(denyText, want) {
					t.Fatalf("%s deny rules missing %q", name, want)
				}
			}
		})
	}
}

func TestLocalClaudeSubagentsDoNotGrantMutationOrShellTools(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("..", "..", ".claude", "agents")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip(".claude/agents is local and not present")
	}
	if err != nil {
		t.Fatalf("read .claude/agents: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // static local permissions fixture path.
			if err != nil {
				t.Fatalf("read subagent file: %v", err)
			}
			toolsLine := firstLineWithPrefix(string(data), "tools:")
			if toolsLine == "" {
				t.Fatalf("%s missing tools frontmatter", entry.Name())
			}
			for _, disallowed := range []string{"Bash", "Write", "Edit"} {
				if frontmatterToolsContain(toolsLine, disallowed) {
					t.Fatalf("%s grants %s in tools frontmatter: %s", entry.Name(), disallowed, toolsLine)
				}
			}
		})
	}
}

func TestLocalClaudeAgentGuidesUseCanonicalSources(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("..", "..", ".claude", "agents")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip(".claude/agents is local and not present")
	}
	if err != nil {
		t.Fatalf("read .claude/agents: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // static local documentation fixture path.
			if err != nil {
				t.Fatalf("read subagent file: %v", err)
			}
			text := string(data)
			for _, forbidden := range []string{"CLAUDE.md", "open_points.md"} {
				if strings.Contains(text, forbidden) {
					t.Fatalf("%s still references stale source %q", entry.Name(), forbidden)
				}
			}
			for _, want := range []string{"AGENTS.md", "DESIGN.md", "SECURITY.md"} {
				if !strings.Contains(text, want) {
					t.Fatalf("%s missing canonical source %q", entry.Name(), want)
				}
			}
		})
	}
}

type localClaudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
}

func readLocalClaudeSettings(t *testing.T, path string) (localClaudeSettings, bool) {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // local permissions fixture; test never reads secret files.
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is local and not present", path)
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var settings localClaudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return settings, true
}

func firstLineWithPrefix(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func frontmatterToolsContain(line, tool string) bool {
	line = strings.TrimPrefix(line, "tools:")
	for _, part := range strings.Split(line, ",") {
		if strings.TrimSpace(part) == tool {
			return true
		}
	}
	return false
}
