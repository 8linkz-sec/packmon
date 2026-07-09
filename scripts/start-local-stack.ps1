$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LocalEnvSecretKeys = @(
    "POSTGRES_PASSWORD",
    "PACKMON_DB_PASSWORD",
    "PACKMON_ADMIN_INITIAL_PASSWORD",
    "PACKMON_ENCRYPTION_KEY",
    "PACKMON_ADMIN_AUDIT_HMAC_KEY"
)

function New-LocalSecret {
    param([int]$Bytes = 32)

    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    } finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($buffer)
}

function Read-EnvValues {
    param([string]$Path)

    $values = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $values
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "" -or $trimmed.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }

        $parts = $line -split "=", 2
        $key = $parts[0].Trim()
        if ($key -ne "") {
            $values[$key] = $parts[1].Trim()
        }
    }
    return $values
}

function Test-MissingEnvValue {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return $true
    }
    $trimmed = $Value.Trim()
    return $trimmed -eq "" -or $trimmed -eq '""' -or $trimmed -eq "''"
}

function Set-EnvFileValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $lines = @(Get-Content -LiteralPath $Path)
    $found = $false
    $pattern = "^\s*$([regex]::Escape($Key))\s*="

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $pattern) {
            $lines[$i] = "$Key=$Value"
            $found = $true
        }
    }

    if (-not $found) {
        $lines += "$Key=$Value"
    }

    Set-Content -LiteralPath $Path -Value $lines -Encoding utf8
}

function Sync-EnvExampleDefaults {
    param(
        [string]$Path,
        [string]$ExamplePath
    )

    $values = Read-EnvValues -Path $Path
    $additions = @()
    foreach ($line in Get-Content -LiteralPath $ExamplePath) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "" -or $trimmed.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }

        $parts = $line -split "=", 2
        $key = $parts[0].Trim()
        if ($key -eq "" -or $values.ContainsKey($key) -or $LocalEnvSecretKeys -contains $key) {
            continue
        }

        $additions += $line
        $values[$key] = $parts[1].Trim()
    }

    if ($additions.Count -eq 0) {
        return $false
    }

    Add-Content -LiteralPath $Path -Value ""
    Add-Content -LiteralPath $Path -Value "# Added from .env.example for current local stack defaults."
    Add-Content -LiteralPath $Path -Value $additions
    return $true
}

function Initialize-LocalEnv {
    $changed = $false

    if (-not (Test-Path -LiteralPath ".env" -PathType Leaf)) {
        Copy-Item -LiteralPath ".env.example" -Destination ".env"
        $changed = $true
    }

    if (Sync-EnvExampleDefaults -Path ".env" -ExamplePath ".env.example") {
        $changed = $true
    }

    $values = Read-EnvValues -Path ".env"
    $postgresPassword = $values["POSTGRES_PASSWORD"]
    $packmonDBPassword = $values["PACKMON_DB_PASSWORD"]

    if (-not (Test-MissingEnvValue $postgresPassword)) {
        $databasePassword = $postgresPassword
    } elseif (-not (Test-MissingEnvValue $packmonDBPassword)) {
        $databasePassword = $packmonDBPassword
    } else {
        $databasePassword = New-LocalSecret -Bytes 32
    }

    if (Test-MissingEnvValue $postgresPassword) {
        Set-EnvFileValue -Path ".env" -Key "POSTGRES_PASSWORD" -Value $databasePassword
        $changed = $true
    }
    if (Test-MissingEnvValue $packmonDBPassword) {
        Set-EnvFileValue -Path ".env" -Key "PACKMON_DB_PASSWORD" -Value $databasePassword
        $changed = $true
    }

    foreach ($entry in @(
        @{ Key = "PACKMON_ADMIN_INITIAL_PASSWORD"; Bytes = 24 },
        @{ Key = "PACKMON_ENCRYPTION_KEY"; Bytes = 32 },
        @{ Key = "PACKMON_ADMIN_AUDIT_HMAC_KEY"; Bytes = 32 }
    )) {
        $current = $values[$entry.Key]
        if (Test-MissingEnvValue $current) {
            Set-EnvFileValue -Path ".env" -Key $entry.Key -Value (New-LocalSecret -Bytes $entry.Bytes)
            $changed = $true
        }
    }

    if ($changed) {
        Write-Host "Created or updated .env with generated local-only secrets."
        $message = "Generated secret values are not printed; use .env for the " +
            "first admin login and review it before shared or production use."
        Write-Host $message
    }
}

function Get-LocalServerPort {
    $values = Read-EnvValues -Path ".env"
    $port = $env:PACKMON_SERVER_PORT
    if (Test-MissingEnvValue $port) {
        $port = $values["PACKMON_SERVER_PORT"]
    }
    if (Test-MissingEnvValue $port) {
        return "8080"
    }
    return $port.Trim().Trim('"').Trim("'")
}

function Test-ReadyEndpoint {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        $statusCode = [int]$response.StatusCode
        return $statusCode -ge 200 -and $statusCode -lt 300
    } catch {
        return $false
    }
}

function Show-LocalStackDiagnostics {
    Write-Host "Docker Compose status:"
    docker compose ps
    Write-Host ""
    Write-Host "Recent packmon-server logs:"
    docker compose logs --tail=120 packmon-server
}

function Wait-LocalStackReady {
    param(
        [string]$ServerPort,
        [int]$TimeoutSeconds = 120
    )

    $readyUrl = "http://127.0.0.1:$ServerPort/readyz"
    Write-Host "Waiting for Packmon readiness at $readyUrl..."
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-ReadyEndpoint -Url $readyUrl) {
            return
        }
        Start-Sleep -Seconds 2
    }

    [Console]::Error.WriteLine(
        "Packmon server did not become ready at $readyUrl within $TimeoutSeconds seconds."
    )
    Show-LocalStackDiagnostics
    throw "Packmon local stack did not become ready."
}

Push-Location $RootDir
try {
    Initialize-LocalEnv
    $serverPort = Get-LocalServerPort

    Write-Host "Preparing Packmon database..."
    docker compose run --build --rm packmon-migrate

    Write-Host "Starting Packmon local Docker stack..."
    docker compose up --build -d

    Wait-LocalStackReady -ServerPort $serverPort

    Write-Host ""
    Write-Host "Packmon local server: http://localhost:$serverPort"
    Write-Host "Admin login:          http://localhost:$serverPort/admin/login"
} finally {
    Pop-Location
}
