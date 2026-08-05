param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "missing required command: gh"
}

if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    throw "release tag must look like v1.2.3"
}

$Prefix = if ($env:PACKMON_INSTALL_PREFIX) { $env:PACKMON_INSTALL_PREFIX } else { Join-Path $HOME ".packmon\bin" }
$BinaryName = "packmon-windows-$Arch.exe"
$BaseUrl = if ($env:PACKMON_BINARY_MIRROR) {
    $env:PACKMON_BINARY_MIRROR.TrimEnd("/")
} else {
    "https://github.com/8linkz-sec/packmon/releases/download/$Version"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("packmon-release-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

try {
    $BinaryPath = Join-Path $TempDir $BinaryName
    $ChecksumsPath = Join-Path $TempDir "checksums.txt"

    Invoke-WebRequest -Uri "$BaseUrl/$BinaryName" -OutFile $BinaryPath
    Invoke-WebRequest -Uri "$BaseUrl/checksums.txt" -OutFile $ChecksumsPath

    $checksumLine = Select-String -Path $ChecksumsPath -Pattern "\s$([regex]::Escape($BinaryName))$" | Select-Object -First 1
    if (-not $checksumLine) {
        throw "checksums.txt does not contain $BinaryName"
    }

    $expectedHash = ($checksumLine.Line -split "\s+")[0].ToLowerInvariant()
    $actualHash = (Get-FileHash $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "checksum verification failed for $BinaryName"
    }

    & gh attestation verify $BinaryPath `
        --repo 8linkz-sec/packmon `
        --signer-workflow 8linkz-sec/packmon/.github/workflows/release.yml `
        --source-ref "refs/tags/$Version"
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub artifact attestation verification failed"
    }

    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    Copy-Item -Force $BinaryPath (Join-Path $Prefix "packmon.exe")
    Write-Host "Installed verified Packmon release $Version to $(Join-Path $Prefix 'packmon.exe')"
} finally {
    Remove-Item -Recurse -Force -LiteralPath $TempDir -ErrorAction SilentlyContinue
}
