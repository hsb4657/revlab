[CmdletBinding()]
param(
    [switch]$All,
    [switch]$InstallPrerequisites,
    [switch]$InstallGhidra,
    [switch]$InstallTools,
    [switch]$SkipPython,
    [switch]$SkipFrontend,
    [switch]$Verify,
    [switch]$PersistEnv,
    [string]$PythonExe = "",
    [string]$NodeExe = ""
)

# REVLab bootstrap for Windows. This file intentionally uses ASCII only so it
# can be started from Windows PowerShell 5.1 regardless of the active codepage.
$ErrorActionPreference = "Stop"

if ($All) {
    $InstallPrerequisites = $true
    $InstallGhidra = $true
    $InstallTools = $true
    $Verify = $true
}
if ($InstallGhidra) {
    $InstallPrerequisites = $true
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backendDir = Join-Path $repoRoot "backend"
$mcpDir = Join-Path $repoRoot "mcp_server"
$frontendDir = Join-Path $repoRoot "frontend\workflow"
$venvDir = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$failures = New-Object System.Collections.Generic.List[string]
$status = [ordered]@{}

function Write-State {
    param(
        [ValidateSet("STEP", "OK", "WARN", "FAIL")]
        [string]$Level,
        [string]$Message
    )
    $colors = @{ STEP = "Cyan"; OK = "Green"; WARN = "Yellow"; FAIL = "Red" }
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $colors[$Level]
}

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message)
    Write-State FAIL $Message
}

function Resolve-Executable {
    param(
        [string]$Explicit,
        [string[]]$Names
    )
    if ($Explicit) {
        $candidate = (Resolve-Path -LiteralPath $Explicit -ErrorAction SilentlyContinue)
        if ($candidate) { return $candidate.Path }
        throw "Executable not found: $Explicit"
    }
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command -and $command.Source) { return $command.Source }
    }
    return $null
}

function Invoke-External {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $FilePath $($Arguments -join ' ')"
    }
}

function Install-WingetPackage {
    param(
        [string]$Id,
        [string]$Label
    )
    $wingetPath = Resolve-Executable -Explicit "" -Names @("winget.exe", "winget")
    if (-not $wingetPath) {
        throw "winget is required to install $Label automatically"
    }
    Write-State STEP "Installing $Label with winget"
    Invoke-External -FilePath $wingetPath -Arguments @(
        "install",
        "--exact",
        "--id", $Id,
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
}

function Find-PythonExecutable {
    $found = Resolve-Executable -Explicit "" -Names @("python.exe", "py.exe")
    if ($found) { return $found }
    $patterns = @(
        (Join-Path $env:LocalAppData "Programs\Python\Python*\python.exe"),
        "C:\Program Files\Python*\python.exe"
    )
    foreach ($pattern in $patterns) {
        $matches = @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
        if ($matches.Count -gt 0) { return $matches[0].FullName }
    }
    return $null
}

function Find-Python311Executable {
    $candidates = @(
        (Join-Path $env:LocalAppData "Programs\Python\Python311\python.exe"),
        "C:\Program Files\Python311\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Find-NodeExecutable {
    $found = Resolve-Executable -Explicit "" -Names @("node.exe", "node")
    if ($found) { return $found }
    $candidate = "C:\Program Files\nodejs\node.exe"
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    return $null
}

function Find-NpmExecutable {
    $found = Resolve-Executable -Explicit "" -Names @("npm.cmd", "npm.exe", "npm")
    if ($found) { return $found }
    $candidate = "C:\Program Files\nodejs\npm.cmd"
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    return $null
}

function Find-JavaExecutable {
    $matches = @(Get-ChildItem -Path "C:\Program Files\Microsoft\jdk-21*\bin\java.exe" -File -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
    if ($matches.Count -gt 0) { return $matches[0].FullName }
    $found = Resolve-Executable -Explicit "" -Names @("java.exe", "java")
    if ($found) { return $found }
    return $null
}

function Find-GhidraHome {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:GHIDRA_HOME) { $candidates.Add($env:GHIDRA_HOME) }
    $candidates.Add((Join-Path $repoRoot "ghidra\runtime"))
    $patterns = @(
        "C:\Program Files\ghidra*",
        "C:\Program Files\Ghidra*",
        "C:\ghidra*",
        "C:\Tools\ghidra*",
        "D:\ghidra*"
    )
    foreach ($pattern in $patterns) {
        Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_.FullName) }
    }
    Get-ChildItem -Path (Join-Path $repoRoot "ghidra") -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $candidates.Add($_.FullName) }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath (Join-Path $candidate "support\analyzeHeadless.bat")) {
            return $candidate
        }
    }
    return $null
}

function Get-JavaMajor {
    param([string]$JavaPath)
    # java writes its version to stderr; temporarily keep that native output
    # from being promoted to a terminating PowerShell error.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = (& $JavaPath -version 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($raw -match 'version\s+"([0-9]+)') { return [int]$Matches[1] }
    return 0
}

Write-State STEP "REVLab environment setup"
Write-Host ("Root: {0}" -f $repoRoot)
Write-Host ("Mode: {0}" -f ($(if ($All) { "all" } else { "core" })))

# Python and the two Python requirement sets share one virtual environment.
if (-not $SkipPython) {
    try {
        Write-State STEP "Checking Python"
        $pythonPath = $null
        if (Test-Path -LiteralPath $venvPython) {
            $pythonPath = (Resolve-Path -LiteralPath $venvPython).Path
        } else {
            $pythonPath = if ($PythonExe) {
                Resolve-Executable -Explicit $PythonExe -Names @()
            } else {
                Find-PythonExecutable
            }
            if (-not $pythonPath -and $InstallPrerequisites) {
                Install-WingetPackage -Id "Python.Python.3.11" -Label "Python 3.11"
                $pythonPath = Find-Python311Executable
                if (-not $pythonPath) { $pythonPath = Find-PythonExecutable }
            }
        }
        if (-not $pythonPath) { throw "Python 3.10 or newer is required" }

        $launcherArgs = @()
        if ([IO.Path]::GetFileName($pythonPath).ToLowerInvariant() -eq "py.exe") {
            $launcherArgs = @("-3")
        }
        $versionText = (& $pythonPath @launcherArgs -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null | Out-String).Trim()
        $versionParts = $versionText.Split(".")
        if ($versionParts.Count -lt 2) { throw "Could not determine Python version" }
        $pyMajor = [int]$versionParts[0]
        $pyMinor = [int]$versionParts[1]
        if (($pyMajor -lt 3) -or (($pyMajor -eq 3) -and ($pyMinor -lt 10))) {
            if ($InstallPrerequisites) {
                Install-WingetPackage -Id "Python.Python.3.11" -Label "Python 3.11"
                $newPythonPath = Find-Python311Executable
                if ($newPythonPath) {
                    $pythonPath = $newPythonPath
                    $launcherArgs = @()
                    $versionText = (& $pythonPath -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null | Out-String).Trim()
                    $versionParts = $versionText.Split(".")
                    $pyMajor = [int]$versionParts[0]
                    $pyMinor = [int]$versionParts[1]
                }
            }
            if (($pyMajor -lt 3) -or (($pyMajor -eq 3) -and ($pyMinor -lt 10))) {
                throw "Python 3.10 or newer is required (found $versionText)"
            }
        }
        Write-State OK "Python $versionText -> $pythonPath"

        if (-not (Test-Path -LiteralPath $venvPython)) {
            Write-State STEP "Creating .venv"
            Invoke-External -FilePath $pythonPath -Arguments ($launcherArgs + @("-m", "venv", $venvDir))
        }
        $pythonPath = (Resolve-Path -LiteralPath $venvPython).Path
        $launcherArgs = @()
        $status.Python = $pythonPath

        Write-State STEP "Installing backend requirements"
        Invoke-External -FilePath $pythonPath -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "-r", (Join-Path $backendDir "requirements.txt"))
        Write-State STEP "Installing MCP requirements"
        Invoke-External -FilePath $pythonPath -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "-r", (Join-Path $mcpDir "requirements.txt"))
        $importCheck = "import fastapi,uvicorn,pefile,capstone,lief,sqlalchemy,fastmcp,mcp; print('python imports ok')"
        Invoke-External -FilePath $pythonPath -Arguments @("-c", $importCheck)
        Write-State OK "Python dependencies are ready"
    } catch {
        Add-Failure ("Python setup: " + $_.Exception.Message)
    }
} else {
    Write-State WARN "Python setup skipped"
}

# Vue Flow is the only npm project in the repository. The generated wf-dist
# directory is served by FastAPI and is rebuilt in place.
if (-not $SkipFrontend) {
    try {
        Write-State STEP "Checking Node.js and npm"
        $nodePath = if ($NodeExe) {
            Resolve-Executable -Explicit $NodeExe -Names @()
        } else {
            Find-NodeExecutable
        }
        if (-not $nodePath -and $InstallPrerequisites) {
            Install-WingetPackage -Id "OpenJS.NodeJS.LTS" -Label "Node.js LTS"
            $nodePath = Find-NodeExecutable
        }
        $npmPath = Find-NpmExecutable
        if (-not $nodePath -or -not $npmPath) { throw "Node.js 18+ and npm are required" }
        $nodeVersion = (& $nodePath --version 2>$null | Out-String).Trim().TrimStart("v")
        $nodeParts = $nodeVersion.Split(".")
        if ($nodeParts.Count -lt 1 -or [int]$nodeParts[0] -lt 18) {
            if ($InstallPrerequisites) {
                Install-WingetPackage -Id "OpenJS.NodeJS.LTS" -Label "Node.js LTS"
                $nodePath = Find-NodeExecutable
                $npmPath = Find-NpmExecutable
                $nodeVersion = (& $nodePath --version 2>$null | Out-String).Trim().TrimStart("v")
                $nodeParts = $nodeVersion.Split(".")
            }
            if ($nodeParts.Count -lt 1 -or [int]$nodeParts[0] -lt 18) {
                throw "Node.js 18 or newer is required (found $nodeVersion)"
            }
        }
        $status.Node = $nodeVersion
        Write-State OK "Node.js $nodeVersion -> $nodePath"
        Push-Location $frontendDir
        try {
            if (Test-Path -LiteralPath "package-lock.json") {
                Write-State STEP "Installing frontend dependencies (npm ci)"
                Invoke-External -FilePath $npmPath -Arguments @("ci", "--no-audit", "--no-fund")
            } else {
                Write-State STEP "Installing frontend dependencies (npm install)"
                Invoke-External -FilePath $npmPath -Arguments @("install", "--no-audit", "--no-fund")
            }
            Write-State STEP "Building workflow frontend"
            Invoke-External -FilePath $npmPath -Arguments @("run", "build")
        } finally {
            Pop-Location
        }
        if (-not (Test-Path -LiteralPath (Join-Path $repoRoot "frontend\wf-dist\index.html"))) {
            throw "Frontend build did not produce frontend/wf-dist/index.html"
        }
        Write-State OK "Frontend build is ready"
    } catch {
        Add-Failure ("Frontend setup: " + $_.Exception.Message)
    }
} else {
    Write-State WARN "Frontend setup skipped"
}

# Ghidra is optional for the core application because it is a large download.
# -All or -InstallGhidra opts into the official installer.
try {
    $ghidraHome = Find-GhidraHome
    $javaPath = $null
    $javaMajor = 0
    if ($ghidraHome -or $InstallGhidra) {
        Write-State STEP "Checking Java for Ghidra"
        $javaPath = Find-JavaExecutable
        if (-not $javaPath -and $InstallPrerequisites) {
            Install-WingetPackage -Id "Microsoft.OpenJDK.21" -Label "Microsoft OpenJDK 21"
            $javaPath = Find-JavaExecutable
        }
        if ($javaPath) {
            $javaMajor = Get-JavaMajor $javaPath
        }
        if ($javaMajor -lt 21 -and $InstallPrerequisites) {
            Install-WingetPackage -Id "Microsoft.OpenJDK.21" -Label "Microsoft OpenJDK 21"
            $javaPath = Find-JavaExecutable
            if ($javaPath) { $javaMajor = Get-JavaMajor $javaPath }
        }
        if ($javaMajor -ge 21) {
            $status.Java = "major $javaMajor -> $javaPath"
            Write-State OK "Java major $javaMajor -> $javaPath"
        } elseif ($InstallGhidra) {
            throw "Java 21 or newer is required before installing Ghidra (found $javaMajor)"
        } else {
            $status.Java = "not found or below 21"
            Write-State WARN "Ghidra is present but Java 21 was not found"
        }
    }
    if ($ghidraHome) {
        $status.Ghidra = $ghidraHome
        Write-State OK "Ghidra available -> $ghidraHome"
    } elseif ($InstallGhidra) {
        Write-State STEP "Running official Ghidra installer (large download)"
        $installer = Join-Path $PSScriptRoot "install-ghidra.ps1"
        Invoke-External -FilePath (Resolve-Executable -Explicit "" -Names @("powershell.exe", "pwsh.exe", "powershell")) -Arguments @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installer)
        $ghidraHome = Find-GhidraHome
        if (-not $ghidraHome) { throw "Ghidra installer completed but analyzeHeadless.bat was not found" }
        $status.Ghidra = $ghidraHome
        Write-State OK "Ghidra installed -> $ghidraHome"
    } else {
        $status.Ghidra = "not installed (optional; use -InstallGhidra or -All)"
        Write-State WARN "Ghidra not installed; decompile nodes will be reported as unavailable"
    }
} catch {
    Add-Failure ("Ghidra setup: " + $_.Exception.Message)
}

if ($PersistEnv -and $status.Ghidra -and ($status.Ghidra -notlike "not installed*")) {
    try {
        [Environment]::SetEnvironmentVariable("GHIDRA_HOME", [string]$status.Ghidra, "User")
        $env:GHIDRA_HOME = [string]$status.Ghidra
        Write-State OK "GHIDRA_HOME persisted for the current user"
    } catch {
        Add-Failure ("Persist GHIDRA_HOME: " + $_.Exception.Message)
    }
}

# UPX and PE-sieve are optional but are useful for the PE unpacking branch.
try {
    $upx = Join-Path $repoRoot "tools\upx\upx.exe"
    $pesieve = Join-Path $repoRoot "tools\pe-sieve\pe-sieve64.exe"
    if ($InstallTools) {
        Write-State STEP "Installing optional PE tools"
        $downloader = Join-Path $PSScriptRoot "download_tools.ps1"
        $psPath = Resolve-Executable -Explicit "" -Names @("powershell.exe", "pwsh.exe", "powershell")
        Invoke-External -FilePath $psPath -Arguments @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $downloader, "-SkipGhidra")
    }
    if (Test-Path -LiteralPath $upx) {
        $status.UPX = $upx
        Write-State OK "UPX available"
    } else {
        $status.UPX = "not installed"
        Write-State WARN "UPX not installed (optional; use -InstallTools or -All)"
    }
    if (Test-Path -LiteralPath $pesieve) {
        $status.PESieve = $pesieve
        Write-State OK "PE-sieve available"
    } else {
        $status.PESieve = "not installed"
        Write-State WARN "PE-sieve not installed (optional; use -InstallTools or -All)"
    }
} catch {
    Add-Failure ("Optional tools setup: " + $_.Exception.Message)
}

if ($Verify -and $status.Python -and (Test-Path -LiteralPath ([string]$status.Python))) {
    try {
        Write-State STEP "Running repository verification"
        Invoke-External -FilePath ([string]$status.Python) -Arguments @("-m", "compileall", "-q", $backendDir)
        Push-Location $repoRoot
        try {
            Invoke-External -FilePath ([string]$status.Python) -Arguments @("-m", "unittest", "discover", "-s", "backend\tests", "-v")
        } finally {
            Pop-Location
        }
        Write-State OK "Python compile and test checks passed"
    } catch {
        Add-Failure ("Verification: " + $_.Exception.Message)
    }
} elseif ($Verify) {
    Write-State WARN "Verification skipped because Python setup did not complete"
}

Write-Host ""
Write-Host "REVLab environment summary" -ForegroundColor Cyan
foreach ($key in $status.Keys) {
    Write-Host ("  {0}: {1}" -f $key, $status[$key])
}
Write-Host ""
Write-Host "Start backend: scripts\start.bat"
Write-Host "Web UI:        http://127.0.0.1:8000/"
Write-Host "Workflow UI:   http://127.0.0.1:8000/wf/"
Write-Host "API docs:      http://127.0.0.1:8000/docs"
Write-Host "MCP HTTP:      http://127.0.0.1:8765/mcp"

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-State FAIL ("Setup finished with {0} error(s)" -f $failures.Count)
    foreach ($failure in $failures) { Write-Host ("  - {0}" -f $failure) }
    exit 1
}
Write-State OK "Setup finished"
exit 0
