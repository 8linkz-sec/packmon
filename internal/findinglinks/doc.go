// Package findinglinks centralizes the policy for safe, user-visible advisory
// and resource links.
//
// The package prefers canonical GHSA, NVD, and RustSec advisory URLs, accepts
// only safe HTTP(S) links for clickable output, keeps unsafe values as plain
// text where appropriate, drops blocked or generic reference pages, and ranks
// lower resource scores ahead of higher scores.
package findinglinks
