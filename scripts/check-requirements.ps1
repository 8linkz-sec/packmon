[CmdletBinding()]
param(
    [ValidateSet("agent", "web", "full", "sbom", "server", "dev")]
    [string]$Profile = "full",

    [string]$Target
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $RootDir "scripts\lib\requirements.ps1")

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

    $versionText = Get-ToolVersion $requirement.Command $resolvedCommand $requirement.Installer
    if ($requirement.Version -ne "any") {
        if ($requirement.Installer -ne "manual") {
            if (-not (Test-VersionEquals $versionText $requirement.Version)) {
                $message = "wrong    {0,-18} found '{1}', need pinned {2}" -f `
                    $requirement.Command, $versionText, $requirement.Version
                Write-Host $message -ForegroundColor Red
                $failures += $requirement
                continue
            }
        } else {
            $checkVersion = $requirement.Command -in @("go", "node", "npm", "python", "mvn")
            if ($checkVersion -and -not (Test-VersionAtLeast $versionText $requirement.Version)) {
                $message = "wrong    {0,-18} found '{1}', need {2}" -f `
                    $requirement.Command, $versionText, $requirement.Version
                Write-Host $message -ForegroundColor Red
                $failures += $requirement
                continue
            }
            if ($requirement.Command -eq "mvn") {
                $javaVersion = Get-MavenJavaVersion $resolvedCommand
                if (-not (Test-VersionAtLeast $javaVersion "17")) {
                    $message = "wrong    {0,-18} Maven uses Java '{1}', need JDK >=17" -f `
                        $requirement.Command, $(if ($javaVersion) { $javaVersion } else { "unknown" })
                    Write-Host $message -ForegroundColor Red
                    $failures += $requirement
                    continue
                }
            }
        }
    }

    if ($versionText) {
        Write-Host ("ok       {0,-18} {1}" -f $requirement.Command, $versionText)
    } else {
        Write-Host ("ok       {0,-18} found" -f $requirement.Command)
    }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    $message = "{0} requirement(s) missing or incompatible for profile '{1}'." -f `
        $failures.Count, $Profile
    Write-Host $message -ForegroundColor Red
    if ($Profile -eq "sbom" -and $Target) {
        Write-Host "Only tools required by the detected target manifests were checked."
    }
    Write-Host "Run scripts/bootstrap for managed tools after installing missing base toolchains."
    exit 1
}

Write-Host ""
Write-Host ("All requirements are available for profile '{0}'." -f $Profile)
