// Package reporthtml contains shared CSS fragments for Packmon's generated
// self-contained HTML reports.
package reporthtml

const DarkBaseThemeCSS = `color-scheme:dark;--bg:#0d1117;--panel:#161b22;` +
	`--border:#30363d;--fg:#c9d1d9;--heading:#e6edf3;--dim:#8b949e;`

const LightBaseThemeCSS = `color-scheme:light;--bg:#ffffff;--panel:#f6f8fa;` +
	`--border:#d0d7de;--fg:#24292f;--heading:#111827;--dim:#57606a;`

const ForcedColorsBaseThemeCSS = `color-scheme:light;--bg:Canvas;--panel:Canvas;` +
	`--border:CanvasText;--fg:CanvasText;--heading:CanvasText;--dim:CanvasText;`

const PrintBaseThemeCSS = `color-scheme:light;--bg:#ffffff;--panel:#ffffff;` +
	`--border:#8c959f;--fg:#111827;--heading:#000000;--dim:#424a53;`
