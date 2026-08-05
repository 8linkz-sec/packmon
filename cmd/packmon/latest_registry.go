package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

const (
	defaultNPMRegistryBaseURL        = "https://registry.npmjs.org"
	defaultPyPIAPIBaseURL            = "https://pypi.org/pypi"
	defaultRubyGemsAPIBaseURL        = "https://rubygems.org/api/v1/gems"
	defaultCargoRegistryAPIBaseURL   = "https://crates.io/api/v1/crates"
	defaultCocoaPodsTrunkAPIBaseURL  = "https://trunk.cocoapods.org/api/v1/pods"
	defaultComposerRepositoryBaseURL = "https://repo.packagist.org/p2"
	defaultGoModuleProxyURL          = "https://proxy.golang.org"
	defaultMavenRepositoryBaseURL    = "https://repo.maven.apache.org/maven2"
	defaultCRANMirrorURL             = "https://cran.r-project.org"
	defaultPubHostedURL              = "https://pub.dev"
	defaultHexAPIBaseURL             = "https://hex.pm/api"
	defaultNuGetV3BaseURL            = "https://api.nuget.org/v3-flatcontainer"
)

type cliRegistryConfig struct {
	NPMRegistryBaseURL        string            `yaml:"npm_registry_base_url"`
	PyPIAPIBaseURL            string            `yaml:"pypi_api_base_url"`
	RubyGemsAPIBaseURL        string            `yaml:"rubygems_api_base_url"`
	CargoRegistryAPIBaseURL   string            `yaml:"cargo_registry_api_base_url"`
	CocoaPodsTrunkAPIBaseURL  string            `yaml:"cocoapods_trunk_api_base_url"`
	ComposerRepositoryBaseURL string            `yaml:"composer_repository_base_url"`
	GoModuleProxyURL          string            `yaml:"go_proxy_url"`
	MavenRepositoryBaseURL    string            `yaml:"maven_repository_base_url"`
	DockerRegistryMirrors     map[string]string `yaml:"docker_registry_mirrors"`
	SwiftPMGitAllowedHosts    []string          `yaml:"swiftpm_git_allowed_hosts"`
	CRANMirrorURL             string            `yaml:"cran_mirror_url"`
	PubHostedURL              string            `yaml:"pub_hosted_url"`
	HexAPIBaseURL             string            `yaml:"hex_api_base_url"`
	NuGetV3BaseURL            string            `yaml:"nuget_v3_base_url"`
}

type latestRegistryConfig struct {
	NPMRegistryBaseURL                  string
	NPMRegistryBaseURLConfigured        bool
	PyPIAPIBaseURL                      string
	PyPIAPIBaseURLConfigured            bool
	RubyGemsAPIBaseURL                  string
	RubyGemsAPIBaseURLConfigured        bool
	CargoRegistryAPIBaseURL             string
	CargoRegistryAPIBaseURLConfigured   bool
	CocoaPodsTrunkAPIBaseURL            string
	CocoaPodsTrunkAPIBaseURLConfigured  bool
	ComposerRepositoryBaseURL           string
	ComposerRepositoryBaseURLConfigured bool
	GoModuleProxyURL                    string
	GoModuleProxyURLConfigured          bool
	MavenRepositoryBaseURL              string
	MavenRepositoryBaseURLConfigured    bool
	DockerRegistryMirrors               map[string]string
	DockerRegistryMirrorsConfigured     bool
	SwiftPMGitAllowedHosts              []string
	SwiftPMGitAllowedHostsConfigured    bool
	CRANMirrorURL                       string
	CRANMirrorURLConfigured             bool
	PubHostedURL                        string
	PubHostedURLConfigured              bool
	HexAPIBaseURL                       string
	HexAPIBaseURLConfigured             bool
	NuGetV3BaseURL                      string
	NuGetV3BaseURLConfigured            bool
}

func defaultLatestRegistryConfig() latestRegistryConfig {
	return latestRegistryConfig{
		NPMRegistryBaseURL:        defaultNPMRegistryBaseURL,
		PyPIAPIBaseURL:            defaultPyPIAPIBaseURL,
		RubyGemsAPIBaseURL:        defaultRubyGemsAPIBaseURL,
		CargoRegistryAPIBaseURL:   defaultCargoRegistryAPIBaseURL,
		CocoaPodsTrunkAPIBaseURL:  defaultCocoaPodsTrunkAPIBaseURL,
		ComposerRepositoryBaseURL: defaultComposerRepositoryBaseURL,
		GoModuleProxyURL:          defaultGoModuleProxyURL,
		MavenRepositoryBaseURL:    defaultMavenRepositoryBaseURL,
		CRANMirrorURL:             defaultCRANMirrorURL,
		PubHostedURL:              defaultPubHostedURL,
		HexAPIBaseURL:             defaultHexAPIBaseURL,
		NuGetV3BaseURL:            defaultNuGetV3BaseURL,
	}
}

func (c latestRegistryConfig) withDefaults() latestRegistryConfig {
	c.NPMRegistryBaseURL = strings.TrimRight(strings.TrimSpace(c.NPMRegistryBaseURL), "/")
	c.PyPIAPIBaseURL = strings.TrimRight(strings.TrimSpace(c.PyPIAPIBaseURL), "/")
	c.RubyGemsAPIBaseURL = strings.TrimRight(strings.TrimSpace(c.RubyGemsAPIBaseURL), "/")
	c.CargoRegistryAPIBaseURL = strings.TrimRight(strings.TrimSpace(c.CargoRegistryAPIBaseURL), "/")
	c.CocoaPodsTrunkAPIBaseURL = strings.TrimRight(strings.TrimSpace(c.CocoaPodsTrunkAPIBaseURL), "/")
	c.ComposerRepositoryBaseURL = strings.TrimRight(strings.TrimSpace(c.ComposerRepositoryBaseURL), "/")
	c.GoModuleProxyURL = normalizeGoProxyOffValue(strings.TrimRight(strings.TrimSpace(c.GoModuleProxyURL), "/"))
	c.MavenRepositoryBaseURL = strings.TrimRight(strings.TrimSpace(c.MavenRepositoryBaseURL), "/")
	c.DockerRegistryMirrors = cloneStringMap(c.DockerRegistryMirrors)
	if len(c.DockerRegistryMirrors) > 0 {
		c.DockerRegistryMirrorsConfigured = true
	}
	c.SwiftPMGitAllowedHosts = dedupStringList(c.SwiftPMGitAllowedHosts)
	if len(c.SwiftPMGitAllowedHosts) > 0 {
		c.SwiftPMGitAllowedHostsConfigured = true
	}
	c.CRANMirrorURL = strings.TrimRight(strings.TrimSpace(c.CRANMirrorURL), "/")
	c.PubHostedURL = strings.TrimRight(strings.TrimSpace(c.PubHostedURL), "/")
	c.HexAPIBaseURL = strings.TrimRight(strings.TrimSpace(c.HexAPIBaseURL), "/")
	c.NuGetV3BaseURL = strings.TrimRight(strings.TrimSpace(c.NuGetV3BaseURL), "/")
	if c.NPMRegistryBaseURL == "" {
		c.NPMRegistryBaseURL = defaultNPMRegistryBaseURL
	} else if c.NPMRegistryBaseURL != defaultNPMRegistryBaseURL {
		c.NPMRegistryBaseURLConfigured = true
	}
	if c.PyPIAPIBaseURL == "" {
		c.PyPIAPIBaseURL = defaultPyPIAPIBaseURL
	} else if c.PyPIAPIBaseURL != defaultPyPIAPIBaseURL {
		c.PyPIAPIBaseURLConfigured = true
	}
	if c.RubyGemsAPIBaseURL == "" {
		c.RubyGemsAPIBaseURL = defaultRubyGemsAPIBaseURL
	} else if c.RubyGemsAPIBaseURL != defaultRubyGemsAPIBaseURL {
		c.RubyGemsAPIBaseURLConfigured = true
	}
	if c.CargoRegistryAPIBaseURL == "" {
		c.CargoRegistryAPIBaseURL = defaultCargoRegistryAPIBaseURL
	} else if c.CargoRegistryAPIBaseURL != defaultCargoRegistryAPIBaseURL {
		c.CargoRegistryAPIBaseURLConfigured = true
	}
	if c.CocoaPodsTrunkAPIBaseURL == "" {
		c.CocoaPodsTrunkAPIBaseURL = defaultCocoaPodsTrunkAPIBaseURL
	} else if c.CocoaPodsTrunkAPIBaseURL != defaultCocoaPodsTrunkAPIBaseURL {
		c.CocoaPodsTrunkAPIBaseURLConfigured = true
	}
	if c.ComposerRepositoryBaseURL == "" {
		c.ComposerRepositoryBaseURL = defaultComposerRepositoryBaseURL
	} else if c.ComposerRepositoryBaseURL != defaultComposerRepositoryBaseURL {
		c.ComposerRepositoryBaseURLConfigured = true
	}
	if c.GoModuleProxyURL == "" {
		c.GoModuleProxyURL = defaultGoModuleProxyURL
	} else if c.GoModuleProxyURL != defaultGoModuleProxyURL {
		c.GoModuleProxyURLConfigured = true
	}
	if c.MavenRepositoryBaseURL == "" {
		c.MavenRepositoryBaseURL = defaultMavenRepositoryBaseURL
	} else if c.MavenRepositoryBaseURL != defaultMavenRepositoryBaseURL {
		c.MavenRepositoryBaseURLConfigured = true
	}
	if c.CRANMirrorURL == "" {
		c.CRANMirrorURL = defaultCRANMirrorURL
	} else if c.CRANMirrorURL != defaultCRANMirrorURL {
		c.CRANMirrorURLConfigured = true
	}
	if c.PubHostedURL == "" {
		c.PubHostedURL = defaultPubHostedURL
	} else if c.PubHostedURL != defaultPubHostedURL {
		c.PubHostedURLConfigured = true
	}
	if c.HexAPIBaseURL == "" {
		c.HexAPIBaseURL = defaultHexAPIBaseURL
	} else if c.HexAPIBaseURL != defaultHexAPIBaseURL {
		c.HexAPIBaseURLConfigured = true
	}
	if c.NuGetV3BaseURL == "" {
		c.NuGetV3BaseURL = defaultNuGetV3BaseURL
	} else if c.NuGetV3BaseURL != defaultNuGetV3BaseURL {
		c.NuGetV3BaseURLConfigured = true
	}
	return c
}

func (c latestRegistryConfig) inheritFallback(fallback latestRegistryConfig) latestRegistryConfig {
	if strings.TrimSpace(c.NPMRegistryBaseURL) == "" {
		c.NPMRegistryBaseURL = fallback.NPMRegistryBaseURL
		c.NPMRegistryBaseURLConfigured = fallback.NPMRegistryBaseURLConfigured
	}
	if strings.TrimSpace(c.PyPIAPIBaseURL) == "" {
		c.PyPIAPIBaseURL = fallback.PyPIAPIBaseURL
		c.PyPIAPIBaseURLConfigured = fallback.PyPIAPIBaseURLConfigured
	}
	if strings.TrimSpace(c.RubyGemsAPIBaseURL) == "" {
		c.RubyGemsAPIBaseURL = fallback.RubyGemsAPIBaseURL
		c.RubyGemsAPIBaseURLConfigured = fallback.RubyGemsAPIBaseURLConfigured
	}
	if strings.TrimSpace(c.CargoRegistryAPIBaseURL) == "" {
		c.CargoRegistryAPIBaseURL = fallback.CargoRegistryAPIBaseURL
		c.CargoRegistryAPIBaseURLConfigured = fallback.CargoRegistryAPIBaseURLConfigured
	}
	if strings.TrimSpace(c.CocoaPodsTrunkAPIBaseURL) == "" {
		c.CocoaPodsTrunkAPIBaseURL = fallback.CocoaPodsTrunkAPIBaseURL
		c.CocoaPodsTrunkAPIBaseURLConfigured = fallback.CocoaPodsTrunkAPIBaseURLConfigured
	}
	if strings.TrimSpace(c.ComposerRepositoryBaseURL) == "" {
		c.ComposerRepositoryBaseURL = fallback.ComposerRepositoryBaseURL
		c.ComposerRepositoryBaseURLConfigured = fallback.ComposerRepositoryBaseURLConfigured
	}
	if strings.TrimSpace(c.GoModuleProxyURL) == "" {
		c.GoModuleProxyURL = fallback.GoModuleProxyURL
		c.GoModuleProxyURLConfigured = fallback.GoModuleProxyURLConfigured
	}
	if strings.TrimSpace(c.MavenRepositoryBaseURL) == "" {
		c.MavenRepositoryBaseURL = fallback.MavenRepositoryBaseURL
		c.MavenRepositoryBaseURLConfigured = fallback.MavenRepositoryBaseURLConfigured
	}
	if len(c.DockerRegistryMirrors) == 0 && len(fallback.DockerRegistryMirrors) > 0 {
		c.DockerRegistryMirrors = cloneStringMap(fallback.DockerRegistryMirrors)
		c.DockerRegistryMirrorsConfigured = fallback.DockerRegistryMirrorsConfigured
	}
	if len(c.SwiftPMGitAllowedHosts) == 0 && len(fallback.SwiftPMGitAllowedHosts) > 0 {
		c.SwiftPMGitAllowedHosts = append([]string(nil), fallback.SwiftPMGitAllowedHosts...)
		c.SwiftPMGitAllowedHostsConfigured = fallback.SwiftPMGitAllowedHostsConfigured
	}
	if strings.TrimSpace(c.CRANMirrorURL) == "" {
		c.CRANMirrorURL = fallback.CRANMirrorURL
		c.CRANMirrorURLConfigured = fallback.CRANMirrorURLConfigured
	}
	if strings.TrimSpace(c.PubHostedURL) == "" {
		c.PubHostedURL = fallback.PubHostedURL
		c.PubHostedURLConfigured = fallback.PubHostedURLConfigured
	}
	if strings.TrimSpace(c.HexAPIBaseURL) == "" {
		c.HexAPIBaseURL = fallback.HexAPIBaseURL
		c.HexAPIBaseURLConfigured = fallback.HexAPIBaseURLConfigured
	}
	if strings.TrimSpace(c.NuGetV3BaseURL) == "" {
		c.NuGetV3BaseURL = fallback.NuGetV3BaseURL
		c.NuGetV3BaseURLConfigured = fallback.NuGetV3BaseURLConfigured
	}
	return c
}

func normalizeCLIRegistryConfig(cfg *cliRegistryConfig) error {
	if cfg == nil {
		return nil
	}
	var err error
	cfg.NPMRegistryBaseURL, err = normalizeLatestRegistryBaseURL("registries.npm_registry_base_url", cfg.NPMRegistryBaseURL)
	if err != nil {
		return err
	}
	cfg.PyPIAPIBaseURL, err = normalizeLatestRegistryBaseURL("registries.pypi_api_base_url", cfg.PyPIAPIBaseURL)
	if err != nil {
		return err
	}
	cfg.RubyGemsAPIBaseURL, err = normalizeLatestRegistryBaseURL("registries.rubygems_api_base_url", cfg.RubyGemsAPIBaseURL)
	if err != nil {
		return err
	}
	cfg.CargoRegistryAPIBaseURL, err = normalizeLatestRegistryBaseURL("registries.cargo_registry_api_base_url", cfg.CargoRegistryAPIBaseURL)
	if err != nil {
		return err
	}
	cfg.CocoaPodsTrunkAPIBaseURL, err = normalizeLatestRegistryBaseURL("registries.cocoapods_trunk_api_base_url", cfg.CocoaPodsTrunkAPIBaseURL)
	if err != nil {
		return err
	}
	cfg.ComposerRepositoryBaseURL, err = normalizeLatestRegistryBaseURL("registries.composer_repository_base_url", cfg.ComposerRepositoryBaseURL)
	if err != nil {
		return err
	}
	cfg.GoModuleProxyURL, err = normalizeGoModuleProxyURL("registries.go_proxy_url", cfg.GoModuleProxyURL)
	if err != nil {
		return err
	}
	cfg.MavenRepositoryBaseURL, err = normalizeLatestRegistryBaseURL("registries.maven_repository_base_url", cfg.MavenRepositoryBaseURL)
	if err != nil {
		return err
	}
	cfg.DockerRegistryMirrors, err = normalizeDockerRegistryMirrorMap("registries.docker_registry_mirrors", cfg.DockerRegistryMirrors)
	if err != nil {
		return err
	}
	cfg.SwiftPMGitAllowedHosts, err = normalizeSwiftPMGitAllowedHosts("registries.swiftpm_git_allowed_hosts", cfg.SwiftPMGitAllowedHosts)
	if err != nil {
		return err
	}
	cfg.CRANMirrorURL, err = normalizeLatestRegistryBaseURL("registries.cran_mirror_url", cfg.CRANMirrorURL)
	if err != nil {
		return err
	}
	cfg.PubHostedURL, err = normalizeLatestRegistryBaseURL("registries.pub_hosted_url", cfg.PubHostedURL)
	if err != nil {
		return err
	}
	cfg.HexAPIBaseURL, err = normalizeLatestRegistryBaseURL("registries.hex_api_base_url", cfg.HexAPIBaseURL)
	if err != nil {
		return err
	}
	cfg.NuGetV3BaseURL, err = normalizeLatestRegistryBaseURL("registries.nuget_v3_base_url", cfg.NuGetV3BaseURL)
	if err != nil {
		return err
	}
	return nil
}

func applyCLIRegistryConfig(settings *scanSettings, cfg cliRegistryConfig) {
	if cfg.NPMRegistryBaseURL != "" {
		settings.LatestRegistry.NPMRegistryBaseURL = cfg.NPMRegistryBaseURL
		settings.LatestRegistry.NPMRegistryBaseURLConfigured = true
	}
	if cfg.PyPIAPIBaseURL != "" {
		settings.LatestRegistry.PyPIAPIBaseURL = cfg.PyPIAPIBaseURL
		settings.LatestRegistry.PyPIAPIBaseURLConfigured = true
	}
	if cfg.RubyGemsAPIBaseURL != "" {
		settings.LatestRegistry.RubyGemsAPIBaseURL = cfg.RubyGemsAPIBaseURL
		settings.LatestRegistry.RubyGemsAPIBaseURLConfigured = true
	}
	if cfg.CargoRegistryAPIBaseURL != "" {
		settings.LatestRegistry.CargoRegistryAPIBaseURL = cfg.CargoRegistryAPIBaseURL
		settings.LatestRegistry.CargoRegistryAPIBaseURLConfigured = true
	}
	if cfg.CocoaPodsTrunkAPIBaseURL != "" {
		settings.LatestRegistry.CocoaPodsTrunkAPIBaseURL = cfg.CocoaPodsTrunkAPIBaseURL
		settings.LatestRegistry.CocoaPodsTrunkAPIBaseURLConfigured = true
	}
	if cfg.ComposerRepositoryBaseURL != "" {
		settings.LatestRegistry.ComposerRepositoryBaseURL = cfg.ComposerRepositoryBaseURL
		settings.LatestRegistry.ComposerRepositoryBaseURLConfigured = true
	}
	if cfg.GoModuleProxyURL != "" {
		settings.LatestRegistry.GoModuleProxyURL = cfg.GoModuleProxyURL
		settings.LatestRegistry.GoModuleProxyURLConfigured = true
	}
	if cfg.MavenRepositoryBaseURL != "" {
		settings.LatestRegistry.MavenRepositoryBaseURL = cfg.MavenRepositoryBaseURL
		settings.LatestRegistry.MavenRepositoryBaseURLConfigured = true
	}
	if len(cfg.DockerRegistryMirrors) > 0 {
		settings.LatestRegistry.DockerRegistryMirrors = mergeStringMaps(settings.LatestRegistry.DockerRegistryMirrors, cfg.DockerRegistryMirrors)
		settings.LatestRegistry.DockerRegistryMirrorsConfigured = true
	}
	if len(cfg.SwiftPMGitAllowedHosts) > 0 {
		settings.LatestRegistry.SwiftPMGitAllowedHosts = mergeStringSlices(settings.LatestRegistry.SwiftPMGitAllowedHosts, cfg.SwiftPMGitAllowedHosts)
		settings.LatestRegistry.SwiftPMGitAllowedHostsConfigured = true
	}
	if cfg.CRANMirrorURL != "" {
		settings.LatestRegistry.CRANMirrorURL = cfg.CRANMirrorURL
		settings.LatestRegistry.CRANMirrorURLConfigured = true
	}
	if cfg.PubHostedURL != "" {
		settings.LatestRegistry.PubHostedURL = cfg.PubHostedURL
		settings.LatestRegistry.PubHostedURLConfigured = true
	}
	if cfg.HexAPIBaseURL != "" {
		settings.LatestRegistry.HexAPIBaseURL = cfg.HexAPIBaseURL
		settings.LatestRegistry.HexAPIBaseURLConfigured = true
	}
	if cfg.NuGetV3BaseURL != "" {
		settings.LatestRegistry.NuGetV3BaseURL = cfg.NuGetV3BaseURL
		settings.LatestRegistry.NuGetV3BaseURLConfigured = true
	}
}

func applyLatestRegistryEnvSettings(settings *scanSettings) error {
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_NPM_REGISTRY_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_NPM_REGISTRY_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.NPMRegistryBaseURL = baseURL
		settings.LatestRegistry.NPMRegistryBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_PYPI_API_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_PYPI_API_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.PyPIAPIBaseURL = baseURL
		settings.LatestRegistry.PyPIAPIBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_RUBYGEMS_API_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_RUBYGEMS_API_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.RubyGemsAPIBaseURL = baseURL
		settings.LatestRegistry.RubyGemsAPIBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_CARGO_REGISTRY_API_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_CARGO_REGISTRY_API_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.CargoRegistryAPIBaseURL = baseURL
		settings.LatestRegistry.CargoRegistryAPIBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_COCOAPODS_TRUNK_API_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_COCOAPODS_TRUNK_API_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.CocoaPodsTrunkAPIBaseURL = baseURL
		settings.LatestRegistry.CocoaPodsTrunkAPIBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_COMPOSER_REPOSITORY_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_COMPOSER_REPOSITORY_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.ComposerRepositoryBaseURL = baseURL
		settings.LatestRegistry.ComposerRepositoryBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_GO_PROXY_URL"), "/")); raw != "" {
		baseURL, err := normalizeGoModuleProxyURL("PACKMON_GO_PROXY_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.GoModuleProxyURL = baseURL
		settings.LatestRegistry.GoModuleProxyURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_MAVEN_REPOSITORY_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_MAVEN_REPOSITORY_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.MavenRepositoryBaseURL = baseURL
		settings.LatestRegistry.MavenRepositoryBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(os.Getenv("PACKMON_DOCKER_REGISTRY_MIRRORS")); raw != "" {
		mirrors, err := parseDockerRegistryMirrorEnv(raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.DockerRegistryMirrors = mergeStringMaps(settings.LatestRegistry.DockerRegistryMirrors, mirrors)
		settings.LatestRegistry.DockerRegistryMirrorsConfigured = true
	}
	if raw := strings.TrimSpace(os.Getenv("PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS")); raw != "" {
		hosts, err := normalizeSwiftPMGitAllowedHosts("PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS", splitCSV(raw))
		if err != nil {
			return err
		}
		settings.LatestRegistry.SwiftPMGitAllowedHosts = hosts
		settings.LatestRegistry.SwiftPMGitAllowedHostsConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_CRAN_MIRROR_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_CRAN_MIRROR_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.CRANMirrorURL = baseURL
		settings.LatestRegistry.CRANMirrorURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_PUB_HOSTED_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_PUB_HOSTED_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.PubHostedURL = baseURL
		settings.LatestRegistry.PubHostedURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_HEX_API_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_HEX_API_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.HexAPIBaseURL = baseURL
		settings.LatestRegistry.HexAPIBaseURLConfigured = true
	}
	if raw := strings.TrimSpace(strings.TrimRight(os.Getenv("PACKMON_NUGET_V3_BASE_URL"), "/")); raw != "" {
		baseURL, err := normalizeLatestRegistryBaseURL("PACKMON_NUGET_V3_BASE_URL", raw)
		if err != nil {
			return err
		}
		settings.LatestRegistry.NuGetV3BaseURL = baseURL
		settings.LatestRegistry.NuGetV3BaseURLConfigured = true
	}
	return nil
}

func normalizeSwiftPMGitAllowedHosts(name string, hosts []string) ([]string, error) {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, raw := range hosts {
		host, err := normalizeSwiftPMGitAllowedHost(name, raw)
		if err != nil {
			return nil, err
		}
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}

func normalizeSwiftPMGitAllowedHost(name, raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" {
		return "", nil
	}
	if strings.Contains(host, "://") ||
		strings.ContainsAny(host, " \t\r\n\x00/@:\\?#") ||
		strings.HasPrefix(host, "-") ||
		strings.HasPrefix(host, ".") ||
		strings.HasSuffix(host, ".") ||
		strings.Contains(host, "..") {
		return "", fmt.Errorf("%s entries must be bare hostnames without scheme, path, port, or credentials", name)
	}
	if host == "localhost" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", fmt.Errorf("%s entries must be non-local hostnames", name)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%s entries must be DNS hostnames", name)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("%s entries must be DNS hostnames", name)
			}
		}
	}
	return host, nil
}

func parseDockerRegistryMirrorEnv(raw string) (map[string]string, error) {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, mirror, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(host) == "" || strings.TrimSpace(mirror) == "" {
			return nil, fmt.Errorf("PACKMON_DOCKER_REGISTRY_MIRRORS entries must use host=https://mirror form")
		}
		out[host] = mirror
	}
	return normalizeDockerRegistryMirrorMap("PACKMON_DOCKER_REGISTRY_MIRRORS", out)
}

func normalizeDockerRegistryMirrorMap(name string, mirrors map[string]string) (map[string]string, error) {
	if len(mirrors) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(mirrors))
	for rawHost, rawMirror := range mirrors {
		host, err := normalizeDockerRegistryMirrorSourceHost(name, rawHost)
		if err != nil {
			return nil, err
		}
		mirror, err := normalizeDockerRegistryMirrorBaseURL(name+"["+host+"]", rawMirror)
		if err != nil {
			return nil, err
		}
		out[host] = mirror
	}
	return out, nil
}

func normalizeDockerRegistryMirrorSourceHost(name, raw string) (string, error) {
	host := normalizeDockerRegistryHost(raw)
	if host == "" {
		return "", fmt.Errorf("%s source host must not be empty", name)
	}
	if !allowedDockerRegistryMirrorSourceHost(host) {
		return "", fmt.Errorf("%s source host %q is not a supported public Docker registry", name, raw)
	}
	return host, nil
}

func normalizeDockerRegistryMirrorBaseURL(name, raw string) (string, error) {
	baseURL, err := normalizeLatestRegistryBaseURL(name, raw)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(strings.Trim(parsed.Hostname(), "[]")); ip != nil && dockerRegistryMirrorIPBlocked(ip) {
		return "", fmt.Errorf("%s must not point at link-local, multicast, or unspecified addresses", name)
	}
	return baseURL, nil
}

func normalizeDockerRegistryHost(raw string) string {
	host := strings.TrimSpace(strings.ToLower(raw))
	host = strings.TrimSuffix(host, ".")
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = strings.Trim(parsedHost, "[]")
	}
	switch host {
	case "docker.io", "index.docker.io":
		return "registry-1.docker.io"
	default:
		return host
	}
}

func allowedDockerRegistryMirrorSourceHost(host string) bool {
	switch normalizeDockerRegistryHost(host) {
	case "asia.gcr.io", "eu.gcr.io", "gcr.io", "ghcr.io", "mcr.microsoft.com",
		"public.ecr.aws", "quay.io", "registry.gitlab.com", "registry.k8s.io",
		"registry-1.docker.io", "us.gcr.io":
		return true
	default:
		return false
	}
}

func dockerRegistryMirrorIPBlocked(ip net.IP) bool {
	return ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeStringMaps(base, override map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = make(map[string]string, len(override))
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func mergeStringSlices(base, override []string) []string {
	return dedupStringList(append(append([]string(nil), base...), override...))
}

func dedupStringList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeGoModuleProxyURL(name, raw string) (string, error) {
	raw = normalizeGoProxyOffValue(raw)
	if raw == "" || raw == "off" {
		return raw, nil
	}
	return normalizeLatestRegistryBaseURL(name, raw)
}

func normalizeGoProxyOffValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "off") {
		return "off"
	}
	return raw
}

func normalizeLatestRegistryBaseURL(name, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%s must be an absolute http(s) URL", name)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%s must not include credentials", name)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must not include query or fragment components", name)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !latestRegistryHostIsLoopback(parsed.Hostname()) {
			return "", fmt.Errorf("%s must use https; http is allowed only for loopback test endpoints", name)
		}
	default:
		return "", fmt.Errorf("%s must use http or https URLs", name)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func latestRegistryHostIsLoopback(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func registryEndpoint(base string, escapedPathParts ...string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "/"
	}
	for _, part := range escapedPathParts {
		base += "/" + strings.Trim(part, "/")
	}
	return base
}
