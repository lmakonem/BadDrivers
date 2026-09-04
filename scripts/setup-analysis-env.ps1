# Windows Driver Analysis Environment Setup
# Enables test signing, prepares for kernel debugging, installs analysis tools

$ErrorActionPreference = 'Stop'

Write-Host "[*] BadDrivers Lab Environment Setup" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] This script requires Administrator privileges" -ForegroundColor Red
    exit 1
}

# 1. Enable Test Signing
Write-Host "[1/5] Enabling test signing mode..."
try {
    $current = bcdedit /enum | Select-String "testsigning"
    if ($current -match "Yes") {
        Write-Host "  [+] Test signing already enabled"
    } else {
        bcdedit /set testsigning on | Out-Null
        Write-Host "  [+] Test signing enabled (reboot required)"
        $needReboot = $true
    }
} catch {
    Write-Host "  [-] Failed: $_" -ForegroundColor Red
}

# 2. Disable Driver Signature Enforcement (one-time boot option)
Write-Host "[2/5] Configuring driver signature enforcement..."
try {
    bcdedit /set nointegritychecks on | Out-Null
    Write-Host "  [+] Integrity checks disabled (reboot required)"
    $needReboot = $true
} catch {
    Write-Host "  [-] Failed: $_" -ForegroundColor Red
}

# 3. Enable kernel debugging (local KD for WinDbg)
Write-Host "[3/5] Enabling local kernel debugging..."
try {
    $kdStatus = bcdedit /enum | Select-String "debug"
    if ($kdStatus -match "Yes") {
        Write-Host "  [+] Kernel debugging already enabled"
    } else {
        bcdedit /debug on | Out-Null
        bcdedit /dbgsettings local | Out-Null
        Write-Host "  [+] Local kernel debugging enabled (reboot required)"
        $needReboot = $true
    }
} catch {
    Write-Host "  [-] Failed: $_" -ForegroundColor Red
}

# 4. Download WinDbg Preview (if not present)
Write-Host "[4/5] Checking for WinDbg..."
$windbgPath = "C:\Program Files\WindowsApps\Microsoft.WinDbg*"
if (Test-Path $windbgPath) {
    Write-Host "  [+] WinDbg already installed"
} else {
    Write-Host "  [*] WinDbg not found - install manually from Microsoft Store:"
    Write-Host "      https://apps.microsoft.com/store/detail/windbg-preview/9PGJGD53TN86"
}

# 5. Create analysis workspace
Write-Host "[5/5] Setting up analysis workspace..."
$workspace = "C:\bad\analysis"
if (-not (Test-Path $workspace)) {
    New-Item -ItemType Directory -Path $workspace | Out-Null
}

# Create subdirectories
$dirs = @("dumps", "symbols", "scripts", "targets")
foreach ($dir in $dirs) {
    $path = Join-Path $workspace $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

Write-Host "  [+] Workspace: $workspace"

# Create a WinDbg script for IOCTL tracing
$windbgScript = @"
.echo *** Driver IOCTL Tracer ***
.echo Breaking on IRP_MJ_DEVICE_CONTROL dispatch

* Set breakpoint on nt!IofCallDriver (all IOCTLs pass through here)
bp nt!IofCallDriver ".printf \"IRP: %p | Device: %p | IOCTL: %p\", @rdx, poi(@rdx+0x40), poi(@rdx+0x18); .echo; g"

* To trace a specific driver's dispatch routine:
* 1. Load driver symbols: .reload /f drivername.sys
* 2. Find DispatchDeviceControl: x drivername!*Dispatch*
* 3. Set breakpoint: bp drivername!DriverDispatchDeviceControl

.echo Ready. Use 'g' to run.
"@

$windbgScript | Out-File (Join-Path $workspace "scripts\ioctl-trace.wds") -Encoding ASCII
Write-Host "  [+] WinDbg IOCTL tracer: $workspace\scripts\ioctl-trace.wds"

# Summary
Write-Host ""
Write-Host "=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration applied:"
Write-Host "  - Test signing: ENABLED"
Write-Host "  - Driver signature enforcement: DISABLED"
Write-Host "  - Local kernel debugging: ENABLED"
Write-Host "  - Workspace: $workspace"
Write-Host ""

if ($needReboot) {
    Write-Host "[!] REBOOT REQUIRED to apply changes" -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Reboot now? (y/N)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Write-Host "[*] Rebooting in 10 seconds..."
        shutdown /r /t 10 /c "BadDrivers lab environment configured - reboot required"
    }
} else {
    Write-Host "[*] No reboot needed (all settings already applied)"
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Install WinDbg Preview from Microsoft Store (if not present)"
Write-Host "  2. Run enum-drivers.ps1 to scan for targets"
Write-Host "  3. Load high-priority drivers in Ghidra for static analysis"
Write-Host "  4. Use WinDbg + ioctl-trace.wds to monitor live IOCTL traffic"
