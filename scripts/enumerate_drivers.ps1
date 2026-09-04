# enumerate_drivers.ps1
# Find a signed vulnerable driver ALREADY present on this host that we can BYOVD
# against for kernel R/W. Read-only. Prints a prioritized candidate list.
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\enumerate_drivers.ps1
$ErrorActionPreference = 'SilentlyContinue'

function Section([string]$t) { Write-Host ""; Write-Host "==== $t ====" }

function IsMicrosoft($p) {
    if (-not $p) { return $false }
    $l = [string]$p
    $l = $l.ToLower()
    if ($l -like "*microsoft*") { return $true }
    if ($l -like "*winsys*")   { return $true }
    if ($l -like "*wi-*")     { return $true }
    if ($l -like "*intel*")   { return $false }   # Intel is NOT "Microsoft" for our purposes; it can ship vuln drivers
    return $false
}

# ---- 1. Running kernel drivers ----
Section "Running drivers (Win32_SystemDriver)"
$drv = Get-CimInstance -ClassName Win32_SystemDriver 2>$null |
        Where-Object { $_.State -eq 'Running' -or $_.State -eq $null } |
        Sort-Object Name
Write-Host ("Count: {0}" -f @($drv).Count)
if ($drv) {
    foreach ($d in $drv) {
        $vendor = [string]$d.Company
        $nonMs  = -not (IsMicrosoft $vendor)
        $tag    = ""
        if ($nonMs) { $tag = "   <== NON-MICROSOFT" }
        Write-Host ("  {0,-30} state={1,-8} vendor={2}{3}" -f $d.Name, $d.State, $vendor, $tag)
    }
}

# ---- 2. DriverStore FileRepository .sys files ----
Section "DriverStore FileRepository (signed .sys on disk)"
$repo = "C:\Windows\System32\DriverStore\FileRepository"
if (Test-Path $repo) {
    $all   = Get-ChildItem -Path $repo -Filter "*.sys" -Recurse -ErrorAction SilentlyContinue
    $comps = $all | ForEach-Object { ($_.DirectoryName -replace [regex]::Escape($repo), "").TrimStart("\") } |
              Sort-Object -Unique
    Write-Host ("Total .sys files:          {0}" -f @($all).Count)
    Write-Host ("Distinct component dirs:   {0}" -f @($comps).Count)
    Write-Host "Sample component dirs (first 80):"
    $sample = @($comps) | Select-Object -First 80
    foreach ($c in $sample) {
        $tr = if ($c.Length -gt 72) { $c.Substring(0,72) } else { $c }
        Write-Host ("    " + $tr)
    }
} else {
    Write-Host "  FileRepository not present at $repo"
}

# ---- 3. Scan for KNOWN vulnerable driver families on disk ----
Section "Known vulnerable driver name scan"
$patterns = @(
  'PDFW','PDFWKRNL','ConTek','Paragon','WDHWDisk','RTCore64','TPwSav',
  'iaStor','AmdAgesa','AmdFx','AmdFvSDK','pkkmfd','nvlddmkm','AmdFxSDK'
)
$roots = @("C:\Windows\System32\drivers", $repo, "C:\Program Files", "C:\Program Files (x86)", "C:\Users")
$hits  = 0
foreach ($p in $patterns) {
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $found = Get-ChildItem -Path $root -Filter ("*" + $p + "*.sys") -Recurse -ErrorAction SilentlyContinue
        if ($found) {
            foreach ($f in $found) {
                $sha = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash
                $sz  = $f.Length
                Write-Host ("  HIT:  {0}   size={1}   SHA256={2}" -f $f.FullName, $sz, $sha)
                $hits++
            }
        }
    }
}
if ($hits -eq 0) { Write-Host "  No known-vulnerable-driver name matches on disk." }

# ---- 4. HVCI / VBS state ----
Section "HVCI / DeviceGuard / VBS state"
$dg = $null
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard 2>$null
} catch { }
if ($dg) {
    Write-Host ("  Win32_DeviceGuard.SecurityFeatureState = {0}  (7=HVCI on, 0=off)" -f $dg.SecurityFeatureState)
} else {
    Write-Host "  Win32_DeviceGuard not available (ARM64 / non-Server build)."
}
$cfg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (Test-Path $cfg) {
    $vbs = (Get-ItemProperty -Path $cfg -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    $lod = (Get-ItemProperty -Path $cfg -Name 'Lod' -ErrorAction SilentlyContinue).Lod
    if ($vbs -ne $null) { Write-Host ("  VBS enabled: {0}" -f $vbs) }
    if ($lod -ne $null) { Write-Host ("  VBS Lod:     {0}" -f $lod) }
} else {
    Write-Host "  DeviceGuard registry key not present."
}

# ---- 5. User-mode accessible device objects ----
Section "User-mode device objects (best effort, safe attempts)"
$candidates = @(
  '\\.\Global\PdFwKrnl','\\.\PdFwKrnl','\\.\Global\AmdFw','\\.\AmdFw',
  '\\.\Global\ConTek','\\.\ConTek','\\.\Global\Paragon','\\.\Paragon',
  '\\.\Global\RTCore64','\\.\RTCore64','\\.\Global\WDHWDisk','\\.\WDHWDisk',
  '\\.\Global\TPwSav','\\.\TPwSav','\\.\Global\iaStor','\\.\iaStor'
)
foreach ($c in $candidates) {
    try {
        $h = [System.IO.File]::Open($c, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
        if ($h) {
            Write-Host ("  OPENABLE:  {0}" -f $c)
            $h.Close()
        }
    } catch { }
}

Section "Done. Review NON-MICROSOFT / HIT / OPENABLE lines to pick a candidate."
