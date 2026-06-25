[CmdletBinding()]
param(
    [ValidateSet("agent", "web", "full", "sbom", "server", "dev")]
    [string]$Profile = "full",

    [string]$Target
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$RequirementsPath = Join-Path $RootDir "requirements\packmon-tools.tsv"
$CheckScript = Join-Path $RootDir "scripts\check-requirements.ps1"

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

function Require-Command {
    param(
        [string]$Command,
        [string]$ForTool
    )
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$ForTool requires '$Command' first. Install the base toolchain and rerun bootstrap."
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

function Install-ManagedTool {
    param([object]$Requirement)

    if ($Requirement.Installer.StartsWith("go-install:")) {
        Require-Command "go" $Requirement.Command
        $module = $Requirement.Installer.Substring("go-install:".Length)
        Write-Host "installing $($Requirement.Command) with go install $module"
        & go install $module
        return
    }

    if ($Requirement.Installer.StartsWith("npm-global:")) {
        Require-Command "npm" $Requirement.Command
        $package = $Requirement.Installer.Substring("npm-global:".Length)
        Write-Host "installing $($Requirement.Command) with npm install --global $package"
        & npm install --global $package
        return
    }

    if ($Requirement.Installer.StartsWith("pip-user:")) {
        Require-Command "python" $Requirement.Command
        $package = $Requirement.Installer.Substring("pip-user:".Length)
        Write-Host "installing $($Requirement.Command) with python -m pip install --user $package"
        & python -m pip install --user $package
        return
    }

    throw "$($Requirement.Command) is a base requirement: $($Requirement.InstallHint)"
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

$manual = @()

foreach ($requirement in $requirements) {
    if (Resolve-RequirementCommand $requirement) {
        Write-Host "already available: $($requirement.Command)"
        continue
    }

    if ($requirement.Installer -eq "manual") {
        $manual += $requirement
        continue
    }

    Install-ManagedTool $requirement
}

if ($manual.Count -gt 0) {
    Write-Host ""
    Write-Host "Install these base requirements manually, then rerun bootstrap:" -ForegroundColor Red
    foreach ($requirement in $manual) {
        Write-Host ("  {0,-12} {1}" -f $requirement.Command, $requirement.InstallHint)
    }
    exit 1
}

if ($Target) {
    & $CheckScript -Profile $Profile -Target $Target
} else {
    & $CheckScript -Profile $Profile
}
