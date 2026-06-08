package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// package-lock.json (npm v2/v3)
// ---------------------------------------------------------------------------

// NPMParser handles package-lock.json files (npm lockfile v2 and v3).
type NPMParser struct{}

// NewNPMParser returns a parser for package-lock.json.
func NewNPMParser() *NPMParser { return &NPMParser{} }

func (p *NPMParser) CanParse(filename string) bool {
	return filename == "package-lock.json"
}

func (p *NPMParser) Ecosystem() domain.Ecosystem { return domain.EcosystemNPM }

// packageLock is the top-level structure of a package-lock.json file.
type packageLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]packageLockPkg `json:"packages"`
	Dependencies    map[string]packageLockDep `json:"dependencies"`
}

type packageLockPkg struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Peer                 bool              `json:"peer"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type packageLockDep struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

func (p *NPMParser) Parse(r io.Reader) ([]domain.Package, error) {
	var lock packageLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("npm: invalid JSON: %w", err)
	}

	var pkgs []domain.Package

	// v2/v3 use the "packages" map. Keys are paths like
	// "node_modules/lodash" or "" for the root package.
	if len(lock.Packages) > 0 {
		metadata := npmPackageMetadata(lock.Packages)
		for key, entry := range lock.Packages {
			if key == "" {
				continue // root project
			}
			name := npmNameFromKey(key)
			if name == "" || entry.Version == "" {
				continue
			}
			pkgs = append(pkgs, domain.Package{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: domain.EcosystemNPM,
				Dev:       entry.Dev || metadata[key].dev,
				Direct:    metadata[key].direct,
				Indirect:  metadata[key].indirect,
				Optional:  entry.Optional || metadata[key].optional,
				Peer:      entry.Peer || metadata[key].peer,
				Via:       append([]string(nil), metadata[key].via...),
				Parents:   append([]domain.PackageParent(nil), metadata[key].parents...),
			})
		}
	} else if len(lock.Dependencies) > 0 {
		// v1 fallback: flat "dependencies" map.
		for name, entry := range lock.Dependencies {
			if name == "" || entry.Version == "" {
				continue
			}
			pkgs = append(pkgs, domain.Package{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: domain.EcosystemNPM,
				Dev:       entry.Dev,
				Direct:    true,
			})
		}
	}

	return dedup(pkgs), nil
}

// npmNameFromKey extracts the package name from a packages-map key.
// Keys look like "node_modules/lodash" or "node_modules/@scope/pkg"
// or nested "node_modules/a/node_modules/b".
func npmNameFromKey(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx == -1 {
		return ""
	}
	return key[idx+len(prefix):]
}

type npmPackageMeta struct {
	direct   bool
	indirect bool
	dev      bool
	optional bool
	peer     bool
	via      []string
	parents  []domain.PackageParent
}

func npmPackageMetadata(packages map[string]packageLockPkg) map[string]npmPackageMeta {
	metadata := make(map[string]npmPackageMeta, len(packages))
	root := packages[""]
	directDeps := npmRootDependencies(root)
	directByKey := make(map[string]npmRootDependency, len(directDeps))
	for name, info := range directDeps {
		if key := npmResolveRootPackageKey(packages, name); key != "" {
			directByKey[key] = info
		}
	}

	for key, entry := range packages {
		if key == "" {
			continue
		}
		name := npmNameFromKey(key)
		if name == "" {
			continue
		}
		rootInfo, direct := directByKey[key]
		metadata[key] = npmPackageMeta{
			direct:   direct,
			indirect: !direct,
			dev:      rootInfo.dev,
			optional: entry.Optional || rootInfo.optional,
			peer:     entry.Peer || rootInfo.peer,
		}
	}

	for rootName := range directDeps {
		rootKey := npmResolveRootPackageKey(packages, rootName)
		if rootKey == "" {
			continue
		}
		for _, depKey := range npmReachableDependencyKeys(packages, rootKey) {
			if depKey == rootKey {
				continue
			}
			meta := metadata[depKey]
			if meta.direct {
				continue
			}
			meta.via = mergeStringSet(meta.via, []string{rootName})
			metadata[depKey] = meta
		}
	}

	for parentKey, parentEntry := range packages {
		if parentKey == "" {
			continue
		}
		parentName := npmNameFromKey(parentKey)
		if parentName == "" || parentEntry.Version == "" {
			continue
		}
		parent := domain.PackageParent{
			Name:      parentName,
			Version:   parentEntry.Version,
			Ecosystem: domain.EcosystemNPM,
		}
		for _, depName := range npmDependencyNames(parentEntry) {
			depKey := npmResolveDependencyKey(packages, parentKey, depName)
			if depKey == "" || depKey == parentKey {
				continue
			}
			meta := metadata[depKey]
			meta.parents = mergePackageParents(meta.parents, []domain.PackageParent{parent})
			metadata[depKey] = meta
		}
	}

	return metadata
}

type npmRootDependency struct {
	dev      bool
	optional bool
	peer     bool
}

func npmRootDependencies(root packageLockPkg) map[string]npmRootDependency {
	out := make(map[string]npmRootDependency)
	add := func(deps map[string]string, dev, optional, peer bool) {
		for name := range deps {
			if strings.TrimSpace(name) == "" {
				continue
			}
			info := out[name]
			info.dev = info.dev || dev
			info.optional = info.optional || optional
			info.peer = info.peer || peer
			out[name] = info
		}
	}
	add(root.Dependencies, false, false, false)
	add(root.DevDependencies, true, false, false)
	add(root.OptionalDependencies, false, true, false)
	add(root.PeerDependencies, false, false, true)
	return out
}

func npmReachableDependencyKeys(packages map[string]packageLockPkg, rootKey string) []string {
	var out []string
	seen := map[string]struct{}{rootKey: {}}
	queue := npmResolvedDependencyKeys(packages, rootKey)
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
		queue = append(queue, npmResolvedDependencyKeys(packages, key)...)
	}
	sort.Strings(out)
	return out
}

func npmResolvedDependencyKeys(packages map[string]packageLockPkg, packageKey string) []string {
	entry := packages[packageKey]
	names := npmDependencyNames(entry)
	out := make([]string, 0, len(names))
	for _, name := range names {
		if depKey := npmResolveDependencyKey(packages, packageKey, name); depKey != "" {
			out = append(out, depKey)
		}
	}
	sort.Strings(out)
	return out
}

func npmDependencyNames(entry packageLockPkg) []string {
	seen := make(map[string]struct{})
	add := func(deps map[string]string) {
		for name := range deps {
			if strings.TrimSpace(name) != "" {
				seen[name] = struct{}{}
			}
		}
	}
	add(entry.Dependencies)
	add(entry.OptionalDependencies)
	add(entry.PeerDependencies)
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func npmResolveRootPackageKey(packages map[string]packageLockPkg, name string) string {
	return npmResolveDependencyKey(packages, "", name)
}

func npmResolveDependencyKey(packages map[string]packageLockPkg, parentKey, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	if parentKey != "" {
		for base := parentKey; ; {
			candidate := base + "/node_modules/" + name
			if _, ok := packages[candidate]; ok {
				return candidate
			}
			idx := strings.LastIndex(base, "/node_modules/")
			if idx == -1 {
				break
			}
			base = base[:idx]
		}
	}
	rootCandidate := "node_modules/" + name
	if _, ok := packages[rootCandidate]; ok {
		return rootCandidate
	}
	var matches []string
	for key := range packages {
		if key != "" && npmNameFromKey(key) == name {
			matches = append(matches, key)
		}
	}
	sort.Strings(matches)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// ---------------------------------------------------------------------------
// yarn.lock (yarn classic v1)
// ---------------------------------------------------------------------------

// YarnParser handles yarn.lock files.
type YarnParser struct{}

// NewYarnParser returns a parser for yarn.lock.
func NewYarnParser() *YarnParser { return &YarnParser{} }

func (p *YarnParser) CanParse(filename string) bool {
	return filename == "yarn.lock"
}

func (p *YarnParser) Ecosystem() domain.Ecosystem { return domain.EcosystemNPM }

// yarnHeaderRe matches resolution header lines such as:
//
//	lodash@^4.17.0, lodash@^4.17.15:
//	"@babel/core@^7.0.0":
var yarnHeaderRe = regexp.MustCompile(`^"?(@?[^@"]+)@[^:]+:?\s*$`)

// yarnVersionRe matches the "  version "x.y.z"" line inside a block.
var yarnVersionRe = regexp.MustCompile(`^\s+version\s+"?([^"]+)"?\s*$`)

func (p *YarnParser) Parse(r io.Reader) ([]domain.Package, error) {
	var (
		pkgs            []domain.Package
		errs            []error
		curName         string
		hasContentLines bool
		matchedHeaders  int
	)

	scanner := newLineScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines.
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		hasContentLines = true

		// Try to match a header line.
		if m := yarnHeaderRe.FindStringSubmatch(line); m != nil {
			curName = unquoteYarnName(m[1])
			matchedHeaders++
			continue
		}

		// Inside a block, look for the version field.
		if curName != "" {
			if m := yarnVersionRe.FindStringSubmatch(line); m != nil {
				version := m[1]
				if version != "" {
					pkgs = append(pkgs, domain.Package{
						Name:      curName,
						Version:   version,
						Ecosystem: domain.EcosystemNPM,
					})
				}
				curName = ""
			}
		}
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("yarn: read error: %w", err))
	}

	// If the file had non-comment content but we could not match any
	// yarn v1 header lines, it is likely a Yarn Berry (v2+) lockfile
	// whose format we do not support yet.
	if len(pkgs) == 0 && hasContentLines && matchedHeaders == 0 {
		errs = append(errs, fmt.Errorf("yarn: lock file format not recognized (possibly Yarn Berry v2+)"))
	}

	return dedup(pkgs), joinErrors(errs)
}

// unquoteYarnName strips surrounding double-quotes if present.
func unquoteYarnName(s string) string {
	return strings.Trim(s, `"`)
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml
// ---------------------------------------------------------------------------

// PnpmParser handles pnpm-lock.yaml files.
type PnpmParser struct{}

// NewPnpmParser returns a parser for pnpm-lock.yaml.
func NewPnpmParser() *PnpmParser { return &PnpmParser{} }

func (p *PnpmParser) CanParse(filename string) bool {
	return filename == "pnpm-lock.yaml"
}

func (p *PnpmParser) Ecosystem() domain.Ecosystem { return domain.EcosystemNPM }

// pnpmLock represents the subset of pnpm-lock.yaml we need.
type pnpmLock struct {
	// pnpm v6+: keys like "/lodash@4.17.21"
	Packages map[string]pnpmPkgEntry `yaml:"packages"`
	// pnpm v9+: snapshot-style with snapshots map
	Snapshots map[string]pnpmSnapshotEntry `yaml:"snapshots"`
}

type pnpmPkgEntry struct {
	Version    string `yaml:"version"`
	Dev        bool   `yaml:"dev"`
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

type pnpmSnapshotEntry struct {
	Dev bool `yaml:"dev"`
}

func (p *PnpmParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("pnpm: read error: %w", err)
	}

	var lock pnpmLock
	if err := yamlUnmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pnpm: invalid YAML: %w", err)
	}

	var pkgs []domain.Package

	for key, entry := range lock.Packages {
		name, version := parsePnpmKey(key, entry.Version)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemNPM,
			Dev:       entry.Dev,
		})
	}

	for key, entry := range lock.Snapshots {
		name, version := parsePnpmKey(key, "")
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemNPM,
			Dev:       entry.Dev,
		})
	}

	return dedup(pkgs), nil
}

// parsePnpmKey extracts name and version from a pnpm packages map key.
// Formats seen across pnpm versions:
//
//	"/lodash@4.17.21"           -> lodash, 4.17.21
//	"/@babel/core@7.24.0"       -> @babel/core, 7.24.0
//	"lodash@4.17.21"            -> lodash, 4.17.21
//	"/lodash/4.17.21"           -> lodash, 4.17.21  (pnpm v5)
//
// When the key does not contain a version, the entryVersion from the YAML
// value is used as fallback.
func parsePnpmKey(key, entryVersion string) (name, version string) {
	// Strip leading slash.
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", ""
	}
	key = stripPnpmPeerSuffix(key)

	// pnpm v6+: name@version
	if atIdx := lastAtIndex(key); atIdx > 0 {
		return key[:atIdx], key[atIdx+1:]
	}

	// pnpm v5: name/version
	if slashIdx := lastNonScopeSlash(key); slashIdx > 0 {
		return key[:slashIdx], key[slashIdx+1:]
	}

	// Fallback to entry version.
	if entryVersion != "" {
		return key, entryVersion
	}
	return key, ""
}

func stripPnpmPeerSuffix(key string) string {
	if idx := strings.Index(key, "("); idx > 0 {
		return key[:idx]
	}
	return key
}

// lastAtIndex returns the index of the last '@' that is not the scope prefix.
func lastAtIndex(s string) int {
	idx := strings.LastIndex(s, "@")
	if idx <= 0 {
		return -1
	}
	return idx
}

// lastNonScopeSlash returns the last '/' that is not part of a scope prefix
// like "@babel/core".
func lastNonScopeSlash(s string) int {
	// If scoped, the first slash separates scope/name -- skip it.
	start := 0
	if strings.HasPrefix(s, "@") {
		first := strings.Index(s, "/")
		if first == -1 {
			return -1
		}
		start = first + 1
	}
	idx := strings.LastIndex(s[start:], "/")
	if idx == -1 {
		return -1
	}
	return start + idx
}
