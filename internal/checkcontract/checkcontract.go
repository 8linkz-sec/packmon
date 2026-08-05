// Package checkcontract defines shared limits for the /api/v1/check contract.
package checkcontract

const (
	// MaxPackagesPerCheck is the maximum number of package coordinates accepted
	// by one /api/v1/check request.
	MaxPackagesPerCheck = 5000

	// MaxPackageNameLength is the maximum accepted package name length.
	MaxPackageNameLength = 512

	// MaxPackageVersionLength is the maximum accepted package version length.
	MaxPackageVersionLength = 256
)
