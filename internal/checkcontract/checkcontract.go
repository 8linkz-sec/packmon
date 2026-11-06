// Package checkcontract defines shared limits for the /api/v1/check contract.
package checkcontract

const (
	// MaxPackagesPerCheck is the maximum number of package coordinates accepted
	// by one /api/v1/check request.
	MaxPackagesPerCheck = 5000

	// MaxScanPackageNameCodePoints is the maximum number of Unicode code points
	// accepted in a raw ScanPackage name before normalization.
	MaxScanPackageNameCodePoints = 512

	// MaxScanPackageVersionCodePoints is the maximum number of Unicode code
	// points accepted in a raw ScanPackage version before normalization.
	MaxScanPackageVersionCodePoints = 256

	// MaxPackageNameUTF8Bytes is the byte-oriented safety limit retained for
	// non-ScanPackage package-coordinate surfaces and outbound reputation PURLs.
	MaxPackageNameUTF8Bytes = 512

	// MaxPackageVersionUTF8Bytes is the byte-oriented safety limit retained for
	// non-ScanPackage package-coordinate surfaces and outbound reputation PURLs.
	MaxPackageVersionUTF8Bytes = 256
)
