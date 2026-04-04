$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Prefix = if ($env:PACKMON_INSTALL_PREFIX) { $env:PACKMON_INSTALL_PREFIX } else { Join-Path $HOME ".packmon\bin" }
$BuildDir = if ($env:PACKMON_BUILD_DIR) { $env:PACKMON_BUILD_DIR } else { Join-Path $RootDir ".build" }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "missing required command: go"
}

New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $HOME ".packmon\db") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $HOME ".packmon\config") | Out-Null

Write-Host "Building packmon binaries..."
Push-Location $RootDir
try {
    go build -o (Join-Path $BuildDir "packmon.exe") ./cmd/packmon
    go build -o (Join-Path $BuildDir "packmon-server.exe") ./cmd/packmon-server
} finally {
    Pop-Location
}

Copy-Item -Force (Join-Path $BuildDir "packmon.exe") (Join-Path $Prefix "packmon.exe")
Copy-Item -Force (Join-Path $BuildDir "packmon-server.exe") (Join-Path $Prefix "packmon-server.exe")

Write-Host "Installed:"
Write-Host "  $(Join-Path $Prefix 'packmon.exe')"
Write-Host "  $(Join-Path $Prefix 'packmon-server.exe')"
Write-Host ""
Write-Host "Suggested next steps:"
Write-Host "  Add $Prefix to PATH"
Write-Host "  packmon version"
Write-Host "  packmon db info"
