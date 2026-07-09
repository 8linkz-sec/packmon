[CmdletBinding()]
param(
    [ValidateSet("agent", "web", "full", "sbom", "server", "dev")]
    [string]$Profile = "full",

    [string]$Target
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CheckScript = Join-Path $RootDir "scripts\check-requirements.ps1"
. (Join-Path $RootDir "scripts\lib\requirements.ps1")

function Require-Command {
    param(
        [string]$Command,
        [string]$ForTool
    )
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$ForTool requires '$Command' first. Install the base toolchain and rerun bootstrap."
    }
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
        Write-Host "installing $($Requirement.Command) with npm install --global --ignore-scripts $package"
        & npm install --global --ignore-scripts $package
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

function Test-RequirementSatisfied {
    param(
        [object]$Requirement,
        [string]$ResolvedCommand
    )
    if (-not $ResolvedCommand) {
        return $false
    }
    if ($Requirement.Version -eq "any") {
        return $true
    }

    $versionText = Get-ToolVersion $Requirement.Command $ResolvedCommand $Requirement.Installer
    if ($Requirement.Installer -ne "manual") {
        return (Test-VersionEquals $versionText $Requirement.Version)
    }

    if ($Requirement.Command -in @("go", "node", "npm", "python", "mvn")) {
        if (-not (Test-VersionAtLeast $versionText $Requirement.Version)) {
            return $false
        }
        if ($Requirement.Command -eq "mvn") {
            return (Test-MavenJavaVersion $ResolvedCommand)
        }
        return $true
    }
    return $true
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
    $resolvedCommand = Resolve-RequirementCommand $requirement
    if ($resolvedCommand -and (Test-RequirementSatisfied $requirement $resolvedCommand)) {
        Write-Host "already available: $($requirement.Command)"
        continue
    }

    if ($requirement.Installer -eq "manual") {
        $manual += $requirement
        continue
    }

    if ($resolvedCommand -and $requirement.Version -ne "any") {
        $versionText = Get-ToolVersion $requirement.Command $resolvedCommand $requirement.Installer
        if (-not $versionText) {
            $versionText = "unknown"
        }
        Write-Host ("upgrading {0} from {1} to pinned {2}" -f $requirement.Command, $versionText, $requirement.Version)
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
