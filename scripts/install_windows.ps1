#Requires -Version 5.1
<#
.SYNOPSIS
    BinjaLattice Windows Installer

.DESCRIPTION
    Complete one-shot installer that:
    1. Installs the Binary Ninja plugin to the correct directory
    2. Creates a Python virtual environment for the MCP server
    3. Installs all dependencies
    4. Outputs ready-to-use MCP configuration
    
    Plugin install path (per Binary Ninja docs):
    https://docs.binary.ninja/guide/plugins.html
    Windows: %APPDATA%\Binary Ninja\plugins

.EXAMPLE
    .\install_windows.ps1
    
.EXAMPLE
    .\install_windows.ps1 -Force
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   BinjaLattice Windows Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Get paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$PluginSource = Join-Path $RepoRoot "plugin\lattice_server_plugin.py"
$PluginConfigSource = Join-Path $RepoRoot "plugin\config.ini"
$McpServerPath = Join-Path $RepoRoot "mcp_server.py"
$RequirementsPath = Join-Path $RepoRoot "requirements.txt"
$VenvPath = Join-Path $RepoRoot ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

# Binary Ninja plugins directory per official documentation
$BNPluginsDir = Join-Path $env:APPDATA "Binary Ninja\plugins"

# ============================================
# STEP 1: Validate environment
# ============================================
Write-Host "[STEP 1/4] Validating environment..." -ForegroundColor Cyan

# Check Python is available
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python not found in PATH." -ForegroundColor Red
    Write-Host "        Please install Python 3.8+ and ensure it's in your PATH." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$pythonVersion = & python --version 2>&1
Write-Host "          Found: $pythonVersion" -ForegroundColor Green

# Check Binary Ninja plugins directory
if (-not (Test-Path $BNPluginsDir)) {
    Write-Host "[ERROR] Binary Ninja plugins directory not found at:" -ForegroundColor Red
    Write-Host "        $BNPluginsDir" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please ensure Binary Ninja is installed and has been run at least once." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "          Found Binary Ninja plugins dir" -ForegroundColor Green

# Check plugin source exists
if (-not (Test-Path $PluginSource)) {
    Write-Host "[ERROR] Plugin file not found. Run from BinjaLattice repo." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""

# ================================================
# STEP 2: Install Binary Ninja plugin & Config
# ================================================
Write-Host "[STEP 2/4] Installing Binary Ninja plugin..." -ForegroundColor Cyan

$PluginDest = Join-Path $BNPluginsDir "lattice_server_plugin.py"
if ((Test-Path $PluginDest) -and -not $Force) {
    Write-Host "          Plugin already exists." -ForegroundColor Yellow
    $response = Read-Host "          Overwrite? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "          Skipping plugin install." -ForegroundColor Yellow
    }
    else {
        Copy-Item -Path $PluginSource -Destination $PluginDest -Force
        Write-Host "          Plugin updated." -ForegroundColor Green
    }
}
else {
    Copy-Item -Path $PluginSource -Destination $PluginDest -Force
    Write-Host "          Plugin installed to:" -ForegroundColor Green
    Write-Host "          $PluginDest" -ForegroundColor White
}
Write-Host ""

$PluginConfigDest = Join-Path $BNPluginsDir "config.ini"
if (Test-Path $PluginConfigSource) {
    # Only copies if the file doesn't exist to avoid wiping user configs
    if (-not (Test-Path $PluginConfigDest)) {
        Copy-Item -Path $PluginConfigSource -Destination $PluginConfigDest
        Write-Host "          Default config.ini created." -ForegroundColor Green
    }
    else {
        Write-Host "          Existing config.ini found. Keeping current settings." -ForegroundColor Cyan
    }
}
else {
    Write-Host "          Config.ini source not found in repo. Without this file default settings will be assumed." -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# STEP 3: Create virtual environment
# ============================================
Write-Host "[STEP 3/4] Setting up Python virtual environment..." -ForegroundColor Cyan

if ((Test-Path $VenvPath) -and -not $Force) {
    Write-Host "          Virtual environment already exists at .venv" -ForegroundColor Yellow
    $response = Read-Host "          Recreate? (y/N)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Remove-Item -Recurse -Force $VenvPath
        & python -m venv $VenvPath
        Write-Host "          Virtual environment recreated." -ForegroundColor Green
    }
}
else {
    if (Test-Path $VenvPath) {
        Remove-Item -Recurse -Force $VenvPath
    }
    & python -m venv $VenvPath
    Write-Host "          Virtual environment created at .venv" -ForegroundColor Green
}
Write-Host ""

# ============================================
# STEP 4: Install dependencies
# ============================================

if (Test-Path $RequirementsPath) {
    try {
        Write-Host "          Updating pip..." -ForegroundColor Gray
        & $VenvPython -m pip install --upgrade pip --quiet 2>&1 | Out-Null
        
        Write-Host "          Installing packages..." -ForegroundColor Gray
        & $VenvPython -m pip install -r $RequirementsPath --quiet 2>&1 | Out-Null
        
        Write-Host "          Dependencies installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to install dependencies: $_" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}
else {
    Write-Host "[WARNING] requirements.txt not found. Installing base defaults..." -ForegroundColor Yellow
    & $VenvPython -m pip install mcp requests --quiet
}
Write-Host ""

# ============================================
# SUCCESS - Output configuration
# ============================================
Write-Host "============================================" -ForegroundColor Green
Write-Host "   Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Binary Ninja Plugin:" -ForegroundColor Cyan
Write-Host "  Installed to: $PluginDest" -ForegroundColor White
Write-Host ""
Write-Host "MCP Server:" -ForegroundColor Cyan
Write-Host "  Python: $VenvPython" -ForegroundColor White
Write-Host "  Server: $McpServerPath" -ForegroundColor White
Write-Host ""
Write-Host "Add this to your MCP configuration (mcp.json):" -ForegroundColor Yellow
Write-Host ""

# Output JSON config with escaped backslashes for Windows paths
$escapedPython = $VenvPython -replace '\\', '\\'
$escapedServer = $McpServerPath -replace '\\', '\\'

Write-Host @"
{
  "mcpServers": {
    "binja-lattice-mcp": {
      "command": "$escapedPython",
      "args": ["$escapedServer"],
      "env": {
        "BNJLAT": "YOUR_API_KEY_HERE"
      }
    }
  }
}
"@ -ForegroundColor Gray

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Restart Binary Ninja"
Write-Host "  2. Open a binary file"
Write-Host "  3. Plugins > Start Lattice Protocol Server"
Write-Host "  4. Copy the API key from the log console"
Write-Host "  5. Replace YOUR_API_KEY_HERE in your mcp.json"
Write-Host ""
Read-Host "Press Enter to exit"
