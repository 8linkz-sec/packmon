package main

import (
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type packageLatestStatus struct {
	Latest     string
	LatestCopy string
	Update     string
	Unknown    bool
}

type dependencyPackageStatus struct {
	Ecosystem  domain.Ecosystem
	SourceType string
	Dev        bool
	Direct     bool
	Indirect   bool
	Optional   bool
	Peer       bool
	Scope      string
	Relation   string
	Flags      string
}

func packageStatusFromListAllPackage(p listAllPackage) dependencyPackageStatus {
	return dependencyPackageStatus{
		Ecosystem:  p.Ecosystem,
		SourceType: p.SourceType,
		Dev:        p.Dev,
		Direct:     p.Direct,
		Indirect:   p.Indirect,
		Optional:   p.Optional,
		Peer:       p.Peer,
		Scope:      p.Scope,
		Relation:   p.Relation,
		Flags:      p.Flags,
	}
}

func packageStatusFromOutdatedPackage(p outdatedPackage) dependencyPackageStatus {
	return dependencyPackageStatus{
		Ecosystem:  p.Ecosystem,
		SourceType: p.SourceType,
		Dev:        p.Dev,
		Direct:     p.Direct,
		Indirect:   p.Indirect,
		Optional:   p.Optional,
		Peer:       p.Peer,
	}
}

func packageStatusScope(p dependencyPackageStatus) string {
	if p.Scope != "" {
		return p.Scope
	}
	switch {
	case p.Ecosystem == domain.EcosystemGitHubActions:
		return "ci"
	case p.SourceType == "sbom":
		return "sbom"
	case p.Dev:
		return "dev"
	default:
		return "runtime"
	}
}

func packageStatusRelation(p dependencyPackageStatus) string {
	if p.Relation != "" {
		return p.Relation
	}
	switch {
	case p.Ecosystem == domain.EcosystemGitHubActions:
		return "workflow"
	case p.Direct:
		return "direct"
	case p.Indirect:
		return "transitive"
	default:
		return "declared"
	}
}

func packageStatusFlags(p dependencyPackageStatus) string {
	if p.Flags != "" {
		return p.Flags
	}
	var flags []string
	if p.Optional {
		flags = append(flags, "optional")
	}
	if p.Peer {
		flags = append(flags, "peer")
	}
	return strings.Join(flags, ", ")
}
