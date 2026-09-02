[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000,
    [int]$McpPort = 8765,
    [switch]$NoMcp,
    [switch]$NoReload,
    [switch]$NoSetup,
    [switch]$AutoSetup
)

# ASCII-only launcher for Windows PowerShell 5.1 compatibility.
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
$envFile = Join-Path $repoRoot ".env"

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $entry = $line.Trim()
        if (-not $entry -or $entry.StartsWith("#")) { continue }
        $separator = $entry.IndexOf("=")
        if ($separator -le 0) { continue }
        $name = $entry.Substring(0, $separator).Trim()
        $value = $entry.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and (
            (($value.StartsWith('"')) -and ($value.EndsWith('"'))) -or
            (($value.StartsWith("'")) -and ($value.EndsWith("'")))
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        Set-Item -Path ("Env:{0}" -f $name) -Value $value
    }
}

function Test-PortInUse {
    param([int]$TargetPort)
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return [bool]($listeners | Where-Object { $_.Port -eq $TargetPort } | Select-Object -First 1)
}

function Test-PythonDependencies {
    if (-not (Test-Path -LiteralPath $pythonPath)) { return $false }
    & $pythonPath -c "import fastapi,uvicorn,pefile,capstone,lief,sqlalchemy,fastmcp,mcp,dnfile" *> $null
    return ($LASTEXITCODE -eq 0)
}

Import-DotEnv $envFile
$frontendIndex = Join-Path $repoRoot "frontend\wf-dist\index.html"
$needsSetup = (-not (Test-PythonDependencies)) -or (-not (Test-Path -LiteralPath $frontendIndex))
$envAutoSetup = $env:REVLAB_AUTO_SETUP -eq "1"
if ($needsSetup -and -not $NoSetup -and ($AutoSetup -or $envAutoSetup)) {
    $setupPath = Join-Path $PSScriptRoot "setup.ps1"
    Write-Host "[INFO] REVLab dependencies are incomplete; running explicitly enabled core setup."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupPath -InstallPrerequisites
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Automatic setup failed. Run scripts\setup.ps1 to inspect the full report."
        exit $LASTEXITCODE
    }
}
if (-not (Test-PythonDependencies)) {
    if ($needsSetup -and -not $NoSetup -and -not ($AutoSetup -or $envAutoSetup)) {
        Write-Error "REVLab dependencies are incomplete. Run scripts\setup.ps1 first, or pass -AutoSetup / set REVLAB_AUTO_SETUP=1."
    } else {
        Write-Error "REVLab .venv is missing or incomplete. Run scripts\setup.ps1 first."
    }
    exit 1
}

Push-Location $repoRoot
$mcpProcess = $null
$exitCode = 0
try {
    if (-not $NoMcp) {
        if (Test-PortInUse $McpPort) {
            Write-Host "[INFO] MCP port $McpPort is already in use; keeping the existing service."
        } else {
            Write-Host "[INFO] Starting MCP HTTP service at http://$BindHost`:$McpPort/mcp"
            $mcpProcess = Start-Process -FilePath $pythonPath `
                -ArgumentList @("-m", "mcp_server.server", "--port", $McpPort) `
                -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru
        }
    }

    Write-Host "[INFO] REVLab web UI: http://$BindHost`:$Port/"
    Write-Host "[INFO] Workflow editor: http://$BindHost`:$Port/wf/"
    $serverArgs = @("-m", "uvicorn", "app.main:app", "--host", $BindHost, "--port", $Port, "--app-dir", "backend")
    if (-not $NoReload) { $serverArgs += "--reload" }
    & $pythonPath @serverArgs
    $exitCode = $LASTEXITCODE
} finally {
    if ($mcpProcess -and -not $mcpProcess.HasExited) {
        Stop-Process -Id $mcpProcess.Id -Force
    }
    Pop-Location
}
exit $exitCode
