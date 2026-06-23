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

$Version = if ($env:PACKMON_VERSION) { $env:PACKMON_VERSION } else { "dev" }
$GitCommit = ""
if (Get-Command git -ErrorAction SilentlyContinue) {
    $GitCommit = (& git -C $RootDir rev-parse --short HEAD 2>$null | Select-Object -First 1)
    if ($GitCommit) {
        $GitCommit = $GitCommit.Trim()
    }
}
$Commit = if ($env:PACKMON_COMMIT) { $env:PACKMON_COMMIT } elseif ($GitCommit) { $GitCommit } else { "none" }
$Date = if ($env:PACKMON_BUILD_DATE) { $env:PACKMON_BUILD_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
$Ldflags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$Date"

Write-Host "Building packmon binaries..."
Push-Location $RootDir
try {
    go build -ldflags $Ldflags -o (Join-Path $BuildDir "packmon.exe") ./cmd/packmon
    go build -ldflags $Ldflags -o (Join-Path $BuildDir "packmon-server.exe") ./cmd/packmon-server
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
