// Package dockerimage builds a metadata-only Docker image inventory for
// list-all reports.
//
// The package parses Dockerfile and Compose image references, records local
// build references separately, and can optionally resolve public registry
// manifest digests through an allowlisted, private-address-aware client. Docker
// inventory rows are display/report data, not server-side package scan inputs.
package dockerimage
