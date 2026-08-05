if (-not $RootDir) {
    throw "RootDir must be set before dot-sourcing scripts/lib/requirements.ps1"
}

$RequirementsPath = Join-Path $RootDir "requirements\packmon-tools.tsv"
$AutoSbomManifestSupportPath = Join-Path $RootDir "internal\sbomgen\auto_sbom_manifests.tsv"

function Read-PackmonRequirements {
    Get-Content -Path $RequirementsPath | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            return
        }
        $fields = $line -split "\|", 8
        if ($fields.Count -ne 8) {
            throw "invalid requirements line: $line"
        }
        [pscustomobject]@{
            Id          = $fields[0]
            Command     = $fields[1]
            Profiles    = $fields[2]
            Required    = [bool]::Parse($fields[3])
            Version     = $fields[4]
            Installer   = $fields[5]
            InstallHint = $fields[6]
            Purpose     = $fields[7]
        }
    }
}

function Test-InProfile {
    param([object]$Requirement)
    return (($Requirement.Profiles -split ",") -contains $Profile)
}

function Add-RequirementId {
    param(
        [hashtable]$Ids,
        [string]$Id
    )
    $Ids[$Id] = $true
}

function Read-AutoSbomManifestSupport {
    if ($null -ne $script:AutoSbomManifestSupport) {
        return $script:AutoSbomManifestSupport
    }
    $script:AutoSbomManifestSupport = @(
        Get-Content -LiteralPath $AutoSbomManifestSupportPath | ForEach-Object {
            $line = $_.Trim()
            if (-not $line -or $line.StartsWith("#")) {
                return
            }
            $fields = $line -split "\|", 5
            if ($fields.Count -ne 5) {
                throw "invalid auto-SBOM manifest support line: $line"
            }
            [pscustomobject]@{
                Name           = $fields[0].Trim()
                Kind           = $fields[1].Trim()
                Ecosystem      = $fields[2].Trim()
                InputKind      = $fields[3].Trim()
                RequirementIds = @($fields[4] -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        }
    )
    return $script:AutoSbomManifestSupport
}

function Test-PoetryPyprojectForRequirements {
    param([string]$Path)

    $section = ""
    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^\[([^\]]+)\]") {
            $section = $Matches[1].Trim()
            continue
        }
        if ($section -ceq "tool.poetry" -and $trimmed -match "^name\s*=") {
            return $true
        }
        if ($section -ceq "tool.poetry.dependencies" -and $trimmed -match "^[^#\s][^=]*=") {
            return $true
        }
    }
    return $false
}

function Add-SbomRequirementIdsForManifest {
    param(
        [hashtable]$Ids,
        [System.IO.FileInfo]$FileInfo
    )

    foreach ($descriptor in Read-AutoSbomManifestSupport) {
        if ($FileInfo.Name -cne $descriptor.Name) {
            continue
        }

        switch ($descriptor.Kind) {
            "detect" {
                if ($descriptor.Name -ceq "package.json") {
                    $dir = $FileInfo.DirectoryName
                    $hasUnsupportedNodeLock = (Test-Path -LiteralPath (Join-Path $dir "pnpm-lock.yaml") -PathType Leaf) -or
                        (Test-Path -LiteralPath (Join-Path $dir "yarn.lock") -PathType Leaf)
                    $hasNpmLock = (Test-Path -LiteralPath (Join-Path $dir "package-lock.json") -PathType Leaf) -or
                        (Test-Path -LiteralPath (Join-Path $dir "npm-shrinkwrap.json") -PathType Leaf)
                    if ($hasUnsupportedNodeLock -and -not $hasNpmLock) {
                        return
                    }
                }
                foreach ($id in $descriptor.RequirementIds) {
                    Add-RequirementId $Ids $id
                }
                return
            }
            "poetry-pyproject" {
                if (Test-PoetryPyprojectForRequirements $FileInfo.FullName) {
                    foreach ($id in $descriptor.RequirementIds) {
                        Add-RequirementId $Ids $id
                    }
                }
                return
            }
            "support-file" {
                return
            }
            "unsupported" {
                return
            }
            default {
                throw "unsupported auto-SBOM manifest kind '$($descriptor.Kind)' for '$($descriptor.Name)'"
            }
        }
    }
}

function Get-SbomRequirementIds {
    param([string]$TargetPath)

    $resolved = Resolve-Path -LiteralPath $TargetPath -ErrorAction Stop
    $rootPath = $resolved.Path
    $ids = @{}
    $skipDirs = @(".git", "node_modules", "vendor", "__pycache__", ".build", ".gotmp")

    Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $relative = $_.FullName.Substring($rootPath.Length).TrimStart("\", "/")
        $parts = $relative -split "[\\/]"
        foreach ($part in $parts) {
            if ($skipDirs -contains $part) {
                return
            }
        }

        Add-SbomRequirementIdsForManifest $ids $_
    }

    return $ids
}

function Get-NumericVersion {
    param([string]$Text)
    if ($Text -match "([0-9]+(?:\.[0-9]+){0,2})") {
        return $Matches[1]
    }
    return ""
}

function ConvertTo-VersionParts {
    param([string]$Version)
    $parts = @()
    foreach ($part in (($Version -replace "^[vV]", "") -split "\.")) {
        if ($part -match "^\d+$") {
            $parts += [int]$part
        }
    }
    while ($parts.Count -lt 3) {
        $parts += 0
    }
    return $parts[0..2]
}

function Test-VersionAtLeast {
    param(
        [string]$Found,
        [string]$Required
    )
    if (-not $Required -or $Required -eq "any") {
        return $true
    }
    $requiredVersion = $Required -replace "^>=", ""
    $foundParts = ConvertTo-VersionParts (Get-NumericVersion $Found)
    $requiredParts = ConvertTo-VersionParts $requiredVersion
    for ($i = 0; $i -lt 3; $i++) {
        if ($foundParts[$i] -gt $requiredParts[$i]) {
            return $true
        }
        if ($foundParts[$i] -lt $requiredParts[$i]) {
            return $false
        }
    }
    return $true
}

function Test-VersionEquals {
    param(
        [string]$Found,
        [string]$Required
    )
    $foundVersion = Get-NumericVersion $Found
    $requiredVersion = Get-NumericVersion $Required
    if (-not $foundVersion -or -not $requiredVersion) {
        return $false
    }
    $foundParts = ConvertTo-VersionParts $foundVersion
    $requiredParts = ConvertTo-VersionParts $requiredVersion
    for ($i = 0; $i -lt 3; $i++) {
        if ($foundParts[$i] -ne $requiredParts[$i]) {
            return $false
        }
    }
    return $true
}

function Get-GoBinaryModuleVersion {
    param([string]$ResolvedCommand)
    if (-not $ResolvedCommand -or -not (Get-Command go -ErrorAction SilentlyContinue)) {
        return ""
    }
    try {
        $moduleInfo = & go version -m $ResolvedCommand 2>$null
        foreach ($line in $moduleInfo) {
            $parts = $line.Trim() -split "\s+"
            if ($parts.Count -ge 3 -and $parts[0] -eq "mod") {
                return $parts[2]
            }
        }
    } catch {
        return ""
    }
    return ""
}

function Get-ToolVersion {
    param(
        [string]$Command,
        [string]$ResolvedCommand,
        [string]$Installer = ""
    )
    if ($Installer.StartsWith("go-install:")) {
        $moduleVersion = Get-GoBinaryModuleVersion $ResolvedCommand
        if ($moduleVersion) {
            return $moduleVersion
        }
    }
    try {
        switch ($Command) {
            "go" { return (& go version 2>$null | Select-Object -First 1) }
            "node" { return (& node --version 2>$null | Select-Object -First 1) }
            "npm" { return (& npm --version 2>$null | Select-Object -First 1) }
            "python" { return (& python --version 2>&1 | Select-Object -First 1) }
            "mvn" { return (& mvn --version 2>$null | Select-Object -First 1) }
            "docker" { return (& docker compose version 2>$null | Select-Object -First 1) }
            "packmon" { return (& $ResolvedCommand version 2>$null | Select-Object -First 1) }
            "cyclonedx-gomod" { return (& cyclonedx-gomod version 2>$null | Select-Object -First 1) }
            "gofumpt" { return (& gofumpt -version 2>$null | Select-Object -First 1) }
            default { return (& $Command --version 2>$null | Select-Object -First 1) }
        }
    } catch {
        return ""
    }
}

function Get-MavenJavaVersion {
    param([string]$ResolvedCommand)
    if (-not $ResolvedCommand) {
        return ""
    }
    try {
        $versionOutput = & $ResolvedCommand --version 2>$null
        foreach ($line in $versionOutput) {
            if ($line -match "^Java version:\s*([^,\s]+)") {
                return $Matches[1]
            }
        }
    } catch {
        return ""
    }
    return ""
}

function Test-MavenJavaVersion {
    param([string]$ResolvedCommand)
    $javaVersion = Get-MavenJavaVersion $ResolvedCommand
    return (Test-VersionAtLeast $javaVersion "17")
}

function Resolve-PackmonCommand {
    $commandInfo = Get-Command packmon -ErrorAction SilentlyContinue
    if ($commandInfo) {
        return $commandInfo.Source
    }
    foreach ($candidate in @(
            (Join-Path (Get-Location) "packmon.exe"),
            (Join-Path (Get-Location) "packmon"),
            (Join-Path $RootDir ".build\packmon.exe"),
            (Join-Path $RootDir ".build\packmon")
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

function Resolve-RequirementCommand {
    param([object]$Requirement)
    if ($Requirement.Command -eq "packmon") {
        return Resolve-PackmonCommand
    }
    $commandInfo = Get-Command $Requirement.Command -ErrorAction SilentlyContinue
    if ($commandInfo) {
        return $commandInfo.Source
    }
    return $null
}
