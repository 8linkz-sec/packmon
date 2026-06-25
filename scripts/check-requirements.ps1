[CmdletBinding()]
param(
    [ValidateSet("agent", "web", "full", "sbom", "server", "dev")]
    [string]$Profile = "full",

    [string]$Target
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$RequirementsPath = Join-Path $RootDir "requirements\packmon-tools.tsv"

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

        $name = $_.Name.ToLowerInvariant()
        switch ($name) {
            "go.mod" {
                Add-RequirementId $ids "go"
                Add-RequirementId $ids "cyclonedx-gomod"
            }
            "package-lock.json" {
                Add-RequirementId $ids "node"
                Add-RequirementId $ids "npm"
                Add-RequirementId $ids "cyclonedx-npm"
            }
            "npm-shrinkwrap.json" {
                Add-RequirementId $ids "node"
                Add-RequirementId $ids "npm"
                Add-RequirementId $ids "cyclonedx-npm"
            }
            "pnpm-lock.yaml" {
                Add-RequirementId $ids "node"
                Add-RequirementId $ids "npm"
                Add-RequirementId $ids "cyclonedx-npm"
            }
            "yarn.lock" {
                Add-RequirementId $ids "node"
                Add-RequirementId $ids "npm"
                Add-RequirementId $ids "cyclonedx-npm"
            }
            "package.json" {
                Add-RequirementId $ids "node"
                Add-RequirementId $ids "npm"
                Add-RequirementId $ids "cyclonedx-npm"
            }
            "requirements.txt" {
                Add-RequirementId $ids "python"
                Add-RequirementId $ids "cyclonedx-py"
            }
            "pyproject.toml" {
                Add-RequirementId $ids "python"
                Add-RequirementId $ids "cyclonedx-py"
            }
            "poetry.lock" {
                Add-RequirementId $ids "python"
                Add-RequirementId $ids "cyclonedx-py"
            }
            "pipfile" {
                Add-RequirementId $ids "python"
                Add-RequirementId $ids "cyclonedx-py"
            }
            "pipfile.lock" {
                Add-RequirementId $ids "python"
                Add-RequirementId $ids "cyclonedx-py"
            }
            "pom.xml" {
                Add-RequirementId $ids "mvn"
            }
        }
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

function Get-ToolVersion {
    param(
        [string]$Command,
        [string]$ResolvedCommand
    )
    try {
        switch ($Command) {
            "go" { return (& go version 2>$null | Select-Object -First 1) }
            "node" { return (& node --version 2>$null | Select-Object -First 1) }
            "npm" { return (& npm --version 2>$null | Select-Object -First 1) }
            "python" { return (& python --version 2>&1 | Select-Object -First 1) }
            "mvn" { return (& mvn --version 2>$null | Select-Object -First 1) }
            "docker" { return (& docker --version 2>$null | Select-Object -First 1) }
            "packmon" { return (& $ResolvedCommand version 2>$null | Select-Object -First 1) }
            "cyclonedx-gomod" { return (& cyclonedx-gomod version 2>$null | Select-Object -First 1) }
            "gofumpt" { return (& gofumpt -version 2>$null | Select-Object -First 1) }
            default { return (& $Command --version 2>$null | Select-Object -First 1) }
        }
    } catch {
        return ""
    }
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

$requirements = @(Read-PackmonRequirements | Where-Object { Test-InProfile $_ })

if ($Profile -eq "sbom" -and $Target) {
    $targetIds = Get-SbomRequirementIds $Target
    if ($targetIds.Count -eq 0) {
        Write-Host ("No auto-SBOM generator requirements detected under '{0}'." -f $Target)
        Write-Host "Packmon can still scan native lockfiles and existing SBOMs without extra tools."
        exit 0
    }
    $requirements = @($requirements | Where-Object { $targetIds.ContainsKey($_.Id) })
    Write-Host ("Detected {0} auto-SBOM requirement group(s) under '{1}'." -f $targetIds.Count, $Target)
}

if ($requirements.Count -eq 0) {
    Write-Host ("No requirements are defined for profile '{0}'." -f $Profile)
    exit 0
}

$failures = @()

foreach ($requirement in $requirements) {
    $resolvedCommand = Resolve-RequirementCommand $requirement
    if (-not $resolvedCommand) {
        Write-Host ("missing  {0,-18} {1}" -f $requirement.Command, $requirement.InstallHint) -ForegroundColor Red
        $failures += $requirement
        continue
    }

    $versionText = Get-ToolVersion $requirement.Command $resolvedCommand
    $checkVersion = $requirement.Command -in @("go", "node", "npm", "python")
    if ($checkVersion -and -not (Test-VersionAtLeast $versionText $requirement.Version)) {
        Write-Host ("wrong    {0,-18} found '{1}', need {2}" -f $requirement.Command, $versionText, $requirement.Version) -ForegroundColor Red
        $failures += $requirement
        continue
    }

    if ($versionText) {
        Write-Host ("ok       {0,-18} {1}" -f $requirement.Command, $versionText)
    } else {
        Write-Host ("ok       {0,-18} found" -f $requirement.Command)
    }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host ("{0} requirement(s) missing or incompatible for profile '{1}'." -f $failures.Count, $Profile) -ForegroundColor Red
    if ($Profile -eq "sbom" -and $Target) {
        Write-Host "Only tools required by the detected target manifests were checked."
    }
    Write-Host "Run scripts/bootstrap for managed tools after installing missing base toolchains."
    exit 1
}

Write-Host ""
Write-Host ("All requirements are available for profile '{0}'." -f $Profile)
