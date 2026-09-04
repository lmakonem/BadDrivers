# IntelPMT.sys Device Enumeration Script
# Tests device accessibility for BYOVD exploitation

Write-Host "[*] IntelPMT.sys Device Enumeration" -ForegroundColor Cyan
Write-Host "="*50 -ForegroundColor Cyan

# Check if driver is loaded
Write-Host "`n[1] Checking if IntelPMT driver is loaded..."
$driver = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -eq "IntelPMT" }
if ($driver) {
    Write-Host "[+] Driver loaded: $($driver.PathName)" -ForegroundColor Green
    Write-Host "    State: $($driver.State)" -ForegroundColor Green
    Write-Host "    Started: $($driver.Started)" -ForegroundColor Green
} else {
    Write-Host "[-] IntelPMT driver not loaded" -ForegroundColor Red
    Write-Host "[*] Attempting to load from System32..."
    try {
        sc.exe create IntelPMT binpath="C:\Windows\System32\drivers\IntelPMT.sys" type=kernel
        sc.exe start IntelPMT
        Write-Host "[+] Driver loaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to load driver: $_" -ForegroundColor Red
        exit 1
    }
}

# Try classic device paths
Write-Host "`n[2] Testing classic device paths..."
$devicePaths = @(
    "\\.\IntelPMT",
    "\\.\INTELPMT",
    "\\.\PMT",
    "\\.\Global\IntelPMT",
    "\\.\IntelPlatformMonitoring"
)

foreach ($path in $devicePaths) {
    try {
        $handle = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
        if ($handle) {
            Write-Host "[+] SUCCESS: Device accessible at $path" -ForegroundColor Green -BackgroundColor DarkGreen
            $handle.Close()
            $script:foundPath = $path
            break
        }
    } catch {
        Write-Host "[-] $path : Not accessible" -ForegroundColor Yellow
    }
}

# Enumerate PnP devices
Write-Host "`n[3] Enumerating PnP devices..."
$pnpDevices = Get-PnpDevice | Where-Object {
    $_.FriendlyName -like "*PMT*" -or
    $_.FriendlyName -like "*Platform Monitoring*" -or
    $_.FriendlyName -like "*Intel*Monitoring*"
}

if ($pnpDevices) {
    Write-Host "[+] Found PnP devices:" -ForegroundColor Green
    $pnpDevices | Select-Object FriendlyName, InstanceId, Status | Format-Table -AutoSize
} else {
    Write-Host "[-] No PMT-related PnP devices found" -ForegroundColor Yellow
}

# Get device interfaces (WDF method)
Write-Host "`n[4] Searching for WDF device interfaces..."
try {
    $setupApiDll = @"
using System;
using System.Runtime.InteropServices;
public class SetupApi {
    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern IntPtr SetupDiGetClassDevs(
        IntPtr ClassGuid, IntPtr Enumerator, IntPtr hwndParent, uint Flags);

    [DllImport("setupapi.dll", SetLastError=true)]
    public static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid,
        uint MemberIndex, IntPtr DeviceInterfaceData);
}
"@
    Add-Type -TypeDefinition $setupApiDll -ErrorAction SilentlyContinue
    Write-Host "[*] SetupAPI loaded, manual enumeration required" -ForegroundColor Yellow
} catch {
    Write-Host "[-] SetupAPI enumeration not available" -ForegroundColor Yellow
}

# Check registry for device interfaces
Write-Host "`n[5] Checking registry for device interfaces..."
$regPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses",
    "HKLM:\SYSTEM\CurrentControlSet\Services\IntelPMT"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        Write-Host "[+] Found registry key: $regPath" -ForegroundColor Green
        Get-ChildItem $regPath -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object {
            Write-Host "    $($_.PSChildName)"
        }
    }
}

# Summary
Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "="*50 -ForegroundColor Cyan

if ($script:foundPath) {
    Write-Host "[SUCCESS] Device is accessible!" -ForegroundColor Green -BackgroundColor DarkGreen
    Write-Host "Device Path: $($script:foundPath)" -ForegroundColor Green
    Write-Host "`nNext Step: Test IOCTL communication"
    Write-Host "  1. Compile test harness: test_intelpmt.cpp"
    Write-Host "  2. Run: test_intelpmt.exe"
} else {
    Write-Host "[BLOCKED] Device not accessible via classic paths" -ForegroundColor Yellow
    Write-Host "`nPossible reasons:"
    Write-Host "  1. WDF device interface (requires GUID enumeration)"
    Write-Host "  2. Driver not creating device object"
    Write-Host "  3. Access restricted to kernel mode only"
    Write-Host "`nNext Step: Reverse engineer in Ghidra to find:"
    Write-Host "  - Device creation function"
    Write-Host "  - Interface GUID"
    Write-Host "  - IOCTL handler entry point"
}

Write-Host "`n[*] Results saved to: Z:\loot\intelpmt_device_enum.txt" -ForegroundColor Cyan
$output | Out-File -FilePath "Z:\loot\intelpmt_device_enum.txt" -Encoding UTF8
