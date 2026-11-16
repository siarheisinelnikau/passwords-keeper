param([switch]$Offline)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    $manifest = Get-Content -LiteralPath Cargo.toml -Raw
    $versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"')
    if (-not $versionMatch.Success) { throw 'Could not read the product version.' }
    $productVersion = $versionMatch.Groups[1].Value
    $cargoArguments = @('build', '--release', '--locked', '--jobs', '2')
    if ($Offline) { $cargoArguments += '--offline' }
    & cargo @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'The release build failed.' }
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    $assetName = "PasswordsKeeper-v$productVersion.exe"
    $assetPath = Join-Path (Get-Location).Path "dist\$assetName"
    Copy-Item -LiteralPath target\release\passwords-keeper.exe -Destination $assetPath
    $digest = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($assetPath + '.sha256', "$digest  $assetName`n", [Text.UTF8Encoding]::new($false))
    Write-Output $assetPath
} finally { Pop-Location }
