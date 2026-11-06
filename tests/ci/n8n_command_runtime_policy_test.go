package ci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	wantN8NCommandImage = "docker.io/n8nio/n8n:2.46.6@sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae"
	wantN8NNodesExclude = "[\"n8n-nodes-base.localFileTrigger\"]"
)

type n8nCommandRuntimeContract struct {
	Image       string            `json:"image"`
	Environment map[string]string `json:"environment"`
}

func TestN8NCommandRuntimePolicyContract(t *testing.T) {
	t.Parallel()

	contract := readN8NCommandRuntimeContract(t)
	if err := validateN8NCommandRuntimeContract(contract); err != nil {
		t.Fatalf("command runtime contract: %v", err)
	}
	if contract.Image != wantN8NCommandImage {
		t.Fatalf("command runtime image = %q, want reviewed image %q", contract.Image, wantN8NCommandImage)
	}

	workflowPaths, err := filepath.Glob(filepath.Join("..", "..", "deploy", "n8n", "*.json"))
	if err != nil {
		t.Fatalf("glob n8n workflows: %v", err)
	}
	var commandWorkflows []string
	for _, path := range workflowPaths {
		if filepath.Base(path) == "command-runtime.json" {
			continue
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // repository-owned workflow fixture
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		var workflow struct {
			Nodes []struct {
				Type string `json:"type"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, node := range workflow.Nodes {
			if node.Type == "n8n-nodes-base.executeCommand" {
				commandWorkflows = append(commandWorkflows, filepath.Base(path))
				break
			}
		}
	}
	sort.Strings(commandWorkflows)
	wantCommandWorkflows := []string{"daily-sync.json", "on-demand-scan.json"}
	if strings.Join(commandWorkflows, "\x00") != strings.Join(wantCommandWorkflows, "\x00") {
		t.Fatalf("Execute Command workflows = %v, want exactly %v", commandWorkflows, wantCommandWorkflows)
	}

	readme := normalizedN8NContractDocument(t, filepath.Join("..", "..", "deploy", "n8n", "README.md"))
	for _, want := range []string{
		contract.Image,
		"NODES_EXCLUDE=" + contract.Environment["NODES_EXCLUDE"],
		"N8N_BLOCK_ENV_ACCESS_IN_NODE=" + contract.Environment["N8N_BLOCK_ENV_ACCESS_IN_NODE"],
		"NODES_EXCLUDE=[]` is not supported",
		"fully trusted",
		"child process launched through Execute Command",
		"main, worker, and webhook process",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("deploy/n8n/README.md is missing command-runtime contract text %q", want)
		}
	}

	design := normalizedN8NContractDocument(t, filepath.Join("..", "..", "DESIGN.md"))
	for _, want := range []string{"deploy/n8n/command-runtime.json", "digest-pinned n8n 2.46.6", "Local File Trigger remains excluded"} {
		if !strings.Contains(design, want) {
			t.Fatalf("DESIGN.md is missing n8n command-runtime contract text %q", want)
		}
	}
	security := normalizedN8NContractDocument(t, filepath.Join("..", "..", "SECURITY.md"))
	for _, want := range []string{"deploy/n8n/command-runtime.json", "Only fully trusted editors", "child process inherits the executor's environment", "NODES_EXCLUDE=[]"} {
		if !strings.Contains(security, want) {
			t.Fatalf("SECURITY.md is missing n8n command-runtime boundary text %q", want)
		}
	}
}

func TestN8NCommandRuntimePolicyRejectsUnsafeMutations(t *testing.T) {
	base := n8nCommandRuntimeContract{
		Image: wantN8NCommandImage,
		Environment: map[string]string{
			"NODES_EXCLUDE":                wantN8NNodesExclude,
			"N8N_BLOCK_ENV_ACCESS_IN_NODE": "true",
		},
	}

	tests := map[string]func(*n8nCommandRuntimeContract){
		"moving image tag": func(contract *n8nCommandRuntimeContract) {
			contract.Image = "docker.io/n8nio/n8n:2.46.6"
		},
		"enable every default-blocked node": func(contract *n8nCommandRuntimeContract) {
			contract.Environment["NODES_EXCLUDE"] = "[]"
		},
		"keep Execute Command excluded": func(contract *n8nCommandRuntimeContract) {
			contract.Environment["NODES_EXCLUDE"] = "[\"n8n-nodes-base.executeCommand\",\"n8n-nodes-base.localFileTrigger\"]"
		},
		"enable Local File Trigger": func(contract *n8nCommandRuntimeContract) {
			contract.Environment["NODES_EXCLUDE"] = "[\"n8n-nodes-base.executeCommand\"]"
		},
		"unblock expression environment": func(contract *n8nCommandRuntimeContract) {
			contract.Environment["N8N_BLOCK_ENV_ACCESS_IN_NODE"] = "false"
		},
		"add secret-looking setting": func(contract *n8nCommandRuntimeContract) {
			contract.Environment["PACKMON_API_KEY"] = "fixture-secret"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			contract := cloneN8NCommandRuntimeContract(base)
			mutate(&contract)
			if err := validateN8NCommandRuntimeContract(contract); err == nil {
				t.Fatal("unsafe mutation unexpectedly satisfied command-runtime policy")
			}
		})
	}
}

func TestN8NCommandRuntimeDocumentRejectsMalformedJSON(t *testing.T) {
	tests := map[string]string{
		"duplicate top-level key":   `{"image":"first","image":"second","environment":{}}`,
		"duplicate environment key": `{"image":"x","environment":{"NODES_EXCLUDE":"[]","NODES_EXCLUDE":"[]"}}`,
		"unknown field":             `{"image":"x","environment":{},"secret":"value"}`,
		"trailing document":         `{"image":"x","environment":{}} {"image":"y","environment":{}}`,
		"wrong environment type":    `{"image":"x","environment":[]}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeN8NCommandRuntimeContract([]byte(document)); err == nil {
				t.Fatal("malformed command-runtime JSON unexpectedly decoded")
			}
		})
	}
}

func readN8NCommandRuntimeContract(t *testing.T) n8nCommandRuntimeContract {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "n8n", "command-runtime.json")
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned policy fixture
	if err != nil {
		t.Fatalf("read command-runtime.json: %v", err)
	}
	contract, err := decodeN8NCommandRuntimeContract(data)
	if err != nil {
		t.Fatalf("parse command-runtime.json: %v", err)
	}
	return contract
}

func decodeN8NCommandRuntimeContract(data []byte) (n8nCommandRuntimeContract, error) {
	if err := rejectDuplicateN8NJSONKeys(data); err != nil {
		return n8nCommandRuntimeContract{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract n8nCommandRuntimeContract
	if err := decoder.Decode(&contract); err != nil {
		return n8nCommandRuntimeContract{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return n8nCommandRuntimeContract{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return contract, nil
}

func rejectDuplicateN8NJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeUniqueN8NJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func consumeUniqueN8NJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key has type %T, want string", keyToken)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueN8NJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueN8NJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	closingDelimiter, ok := closing.(json.Delim)
	if !ok || (delimiter == '{' && closingDelimiter != '}') || (delimiter == '[' && closingDelimiter != ']') {
		return fmt.Errorf("mismatched JSON delimiters %q and %v", delimiter, closing)
	}
	return nil
}

func validateN8NCommandRuntimeContract(contract n8nCommandRuntimeContract) error {
	imagePattern := regexp.MustCompile(`^docker\.io/n8nio/n8n:2\.46\.6@sha256:[0-9a-f]{64}$`)
	if !imagePattern.MatchString(contract.Image) || contract.Image != wantN8NCommandImage {
		return fmt.Errorf("image %q is not the reviewed n8n 2.46.6 multiarch digest", contract.Image)
	}
	if len(contract.Environment) != 2 {
		return fmt.Errorf("environment has %d keys, want exactly the two reviewed policy keys", len(contract.Environment))
	}
	if got := contract.Environment["NODES_EXCLUDE"]; got != wantN8NNodesExclude {
		return fmt.Errorf("NODES_EXCLUDE = %q, want only Local File Trigger excluded", got)
	}
	if got := contract.Environment["N8N_BLOCK_ENV_ACCESS_IN_NODE"]; got != "true" {
		return fmt.Errorf("N8N_BLOCK_ENV_ACCESS_IN_NODE = %q, want true", got)
	}
	return nil
}

func cloneN8NCommandRuntimeContract(contract n8nCommandRuntimeContract) n8nCommandRuntimeContract {
	cloned := n8nCommandRuntimeContract{Image: contract.Image, Environment: make(map[string]string, len(contract.Environment))}
	for key, value := range contract.Environment {
		cloned.Environment[key] = value
	}
	return cloned
}

func normalizedN8NContractDocument(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned documentation fixture
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Join(strings.Fields(string(data)), " ")
}
