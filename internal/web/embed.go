package web

import "embed"

// content holds the embedded templates and static assets.
//
//go:embed templates static
var content embed.FS
