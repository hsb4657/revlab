[CmdletBinding()]
param(
    [switch]$SkipGhidra,
    [switch]$SkipUPX,
    [switch]$SkipPESieve
)

# Official tool bootstrap. This script is ASCII-only for Windows PowerShell 5.1.
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$tools = Join-Path $root "tools"
$downloads = Join-Path $tools "downloads"
New-Item -ItemType Directory -Force -Path $tools, $downloads | Out-Null

function Get-VerifiedFile {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Sha256 = ""
    )
    if (-not (Test-Path -LiteralPath $Destination)) {
        Write-Host "[STEP] Downloading $Url"
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
    if ($Sha256) {
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $Sha256.ToLowerInvariant()) {
            throw "SHA256 mismatch for ${Destination}: $actual"
        }
    }
}

function Copy-FirstMatch {
    param(
        [string]$Root,
        [string]$Filter,
        [string]$Destination
    )
    $match = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Filter |
        Select-Object -First 1
    if (-not $match) { throw "Expected file not found after extraction: $Filter" }
    Copy-Item -LiteralPath $match.FullName -Destination $Destination -Force
}

if (-not $SkipUPX) {
    $upxVersion = "4.2.4"
    $upxDir = Join-Path $tools "upx"
    $upxExe = Join-Path $upxDir "upx.exe"
    if (Test-Path -LiteralPath $upxExe) {
        Write-Host "[OK] UPX available -> $upxExe"
    } else {
        $upxZip = Join-Path $downloads "upx-$upxVersion-win64.zip"
        $upxStage = Join-Path $downloads "upx-stage"
        Get-VerifiedFile -Url "https://github.com/upx/upx/releases/download/v$upxVersion/upx-$upxVersion-win64.zip" -Destination $upxZip
        if (Test-Path -LiteralPath $upxStage) { Remove-Item -LiteralPath $upxStage -Recurse -Force }
        Expand-Archive -LiteralPath $upxZip -DestinationPath $upxStage -Force
        New-Item -ItemType Directory -Force -Path $upxDir | Out-Null
        Copy-FirstMatch -Root $upxStage -Filter "upx.exe" -Destination $upxExe
        Write-Host "[OK] UPX installed -> $upxExe"
    }
}

if (-not $SkipPESieve) {
    # v0.4.1 is the current stable Windows x64 release. The SHA-256 is pinned
    # to the official archive so a failed or altered download is rejected.
    $peSieveVersion = "0.4.1"
    $peSieveSha256 = "792d1c9ab61dacedf2e2ec2d31e115c519c529ae8353a7c0ef6d00e01db0226e"
    $peSieveDir = Join-Path $tools "pe-sieve"
    $peSieveExe = Join-Path $peSieveDir "pe-sieve64.exe"
    if (Test-Path -LiteralPath $peSieveExe) {
        Write-Host "[OK] PE-sieve available -> $peSieveExe"
    } else {
        $peSieveZip = Join-Path $downloads "pe-sieve64-v$peSieveVersion.zip"
        $peSieveStage = Join-Path $downloads "pe-sieve-stage"
        Get-VerifiedFile -Url "https://github.com/hasherezade/pe-sieve/releases/download/v$peSieveVersion/pe-sieve64.zip" -Destination $peSieveZip -Sha256 $peSieveSha256
        if (Test-Path -LiteralPath $peSieveStage) { Remove-Item -LiteralPath $peSieveStage -Recurse -Force }
        Expand-Archive -LiteralPath $peSieveZip -DestinationPath $peSieveStage -Force
        New-Item -ItemType Directory -Force -Path $peSieveDir | Out-Null
        Copy-FirstMatch -Root $peSieveStage -Filter "pe-sieve.exe" -Destination $peSieveExe
        Write-Host "[OK] PE-sieve installed -> $peSieveExe"
    }
}

if (-not $SkipGhidra) {
    $installer = Join-Path $PSScriptRoot "install-ghidra.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
    if ($LASTEXITCODE -ne 0) { throw "Ghidra installer failed with code $LASTEXITCODE" }
}

Write-Host "[OK] Tool bootstrap completed"
