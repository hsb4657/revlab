# REVLab 外部工具下载脚本(UPX / pe-sieve / Ghidra)
# 用法: powershell -ExecutionPolicy Bypass -File scripts\download_tools.ps1 [-SkipGhidra]
param(
    [switch]$SkipGhidra
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root "tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null

function Get-File {
    param($Url, $Out)
    Write-Host "下载: $Url"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -L -o $Out $Url 2>$null
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Out
    }
    if (-not (Test-Path $Out)) { throw "下载失败: $Url" }
    Write-Host "  -> $Out"
}

# ---------- UPX ----------
$upxVer = "4.2.4"
$upxZip = Join-Path $tools "upx-$upxVer-win64.zip"
$upxDir = Join-Path $tools "upx"
if (-not (Test-Path (Join-Path $upxDir "upx.exe"))) {
    Get-File "https://github.com/upx/upx/releases/download/v$upxVer/upx-$upxVer-win64.zip" $upxZip
    Expand-Archive -Force $upxZip (Join-Path $tools "upx_tmp")
    New-Item -ItemType Directory -Force -Path $upxDir | Out-Null
    Copy-Item (Join-Path $tools "upx_tmp\*\upx.exe") $upxDir -Force
    Remove-Item -Recurse -Force (Join-Path $tools "upx_tmp")
    Write-Host "[OK] UPX -> $upxDir\upx.exe"
} else { Write-Host "[SKIP] UPX 已存在" }

# ---------- pe-sieve ----------
$psVer = "0.3.11"
$psDir = Join-Path $tools "pe-sieve"
if (-not (Test-Path (Join-Path $psDir "pe-sieve64.exe"))) {
    New-Item -ItemType Directory -Force -Path $psDir | Out-Null
    Get-File "https://github.com/hasherezade/pe-sieve/releases/download/v$psVer/pe-sieve64.exe" (Join-Path $psDir "pe-sieve64.exe")
    Write-Host "[OK] pe-sieve -> $psDir\pe-sieve64.exe"
} else { Write-Host "[SKIP] pe-sieve 已存在" }

# ---------- Ghidra ----------
if (-not $SkipGhidra) {
    $ghidraVer = "11.1.2"
    $ghidraZip = Join-Path $tools "ghidra.zip"
    $ghidraHome = Join-Path $root "ghidra\ghidra_$($ghidraVer)_PUBLIC"
    if (-not (Test-Path (Join-Path $ghidraHome "support\analyzeHeadless.bat"))) {
        Write-Host "下载 Ghidra $ghidraVer (~500MB),可能需要较长时间..."
        Get-File "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${ghidraVer}_build/ghidra_${ghidraVer}_PUBLIC_20241119.zip" $ghidraZip
        Expand-Archive -Force $ghidraZip (Join-Path $root "ghidra")
        Write-Host "[OK] Ghidra -> $ghidraHome"
    } else { Write-Host "[SKIP] Ghidra 已存在" }
}

Write-Host ""
Write-Host "完成。可启动: scripts\start.bat"
