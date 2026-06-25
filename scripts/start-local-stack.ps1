$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

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

function Initialize-LocalEnv {
    $changed = $false

    if (-not (Test-Path -LiteralPath ".env" -PathType Leaf)) {
        Copy-Item -LiteralPath ".env.example" -Destination ".env"
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
        @{ Key = "PACKMON_ENCRYPTION_KEY"; Bytes = 32 }
    )) {
        $current = $values[$entry.Key]
        if (Test-MissingEnvValue $current) {
            Set-EnvFileValue -Path ".env" -Key $entry.Key -Value (New-LocalSecret -Bytes $entry.Bytes)
            $changed = $true
        }
    }

    if ($changed) {
        Write-Host "Created or updated .env with generated local-only secrets."
        Write-Host "Generated secret values are not printed; use .env for the first admin login and review it before shared or production use."
    }
}

Push-Location $RootDir
try {
    Initialize-LocalEnv

    Write-Host "Preparing Packmon database..."
    docker compose run --build --rm packmon-migrate

    Write-Host "Starting Packmon local Docker stack..."
    docker compose up --build -d

    Write-Host ""
    Write-Host "Packmon local server: http://localhost:8080"
    Write-Host "Admin login:          http://localhost:8080/admin/login"
} finally {
    Pop-Location
}
