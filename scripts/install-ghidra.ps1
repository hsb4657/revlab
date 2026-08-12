$ErrorActionPreference = 'Stop'

# Download and install the latest official Ghidra release into the repository.
# The script is idempotent: an existing, matching archive is reused and the
# extracted runtime is replaced only after a complete archive is available.
$repoRoot = Split-Path -Parent $PSScriptRoot
$installRoot = Join-Path $repoRoot 'ghidra\runtime'
$downloadRoot = Join-Path $repoRoot 'workspace\downloads'
New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null

try {
  $release = Invoke-RestMethod -Headers @{ 'User-Agent' = 'REVLab' } `
    'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest'
  $asset = $release.assets |
    Where-Object { $_.name -match '^ghidra_.*_PUBLIC_.*\.zip$' } |
    Select-Object -First 1
} catch {
  # GitHub API rate limits are common on shared CI/public networks. Keep a
  # pinned official fallback so a fresh open-source checkout remains usable.
  $release = [pscustomobject]@{ tag_name = 'Ghidra_12.1.2_build' }
  $asset = [pscustomobject]@{
    name = 'ghidra_12.1.2_PUBLIC_20260605.zip'
    size = 572803866
    digest = 'sha256:b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d'
    browser_download_url = 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip'
  }
}
if (-not $asset) { throw 'Official Ghidra release asset not found' }

$zip = Join-Path $downloadRoot $asset.name
if (-not (Test-Path -LiteralPath $zip) -or
    (Get-Item -LiteralPath $zip).Length -ne $asset.size) {
  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
}

$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$expected = (($asset.digest -replace '^sha256:', '').ToLowerInvariant())
if ($expected -and $hash -ne $expected) {
  throw "Ghidra ZIP SHA256 mismatch: $hash (expected $expected)"
}

$stage = Join-Path $downloadRoot 'ghidra-stage'
if (Test-Path -LiteralPath $stage) {
  Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force
$payload = Get-ChildItem -LiteralPath $stage -Directory |
  Where-Object { Test-Path (Join-Path $_.FullName 'support\analyzeHeadless.bat') } |
  Select-Object -First 1
if (-not $payload) { throw 'support\analyzeHeadless.bat not found after extraction' }

$parent = Split-Path -Parent $installRoot
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$stagedRuntime = Join-Path $stage 'runtime'
Move-Item -LiteralPath $payload.FullName -Destination $stagedRuntime
if (Test-Path -LiteralPath $installRoot) {
  Remove-Item -LiteralPath $installRoot -Recurse -Force
}
Move-Item -LiteralPath $stagedRuntime -Destination $installRoot

[pscustomobject]@{
  version = $release.tag_name
  home = $installRoot
  zip = $zip
  sha256 = $hash
} | ConvertTo-Json -Compress
