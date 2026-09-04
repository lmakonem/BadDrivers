# Driver Vulnerability Discovery - Enumeration Script
# Scans Windows drivers for exposed device objects and IOCTL interfaces
# Output: JSON manifest for Ghidra analysis pipeline

$ErrorActionPreference = 'SilentlyContinue'
$results = @()

Write-Host "[*] Enumerating System32\drivers..."

# Phase 1: File system scan
Get-ChildItem C:\Windows\System32\drivers\*.sys | ForEach-Object {
    $file = $_
    $sig = Get-AuthenticodeSignature $file
    $hash = (Get-FileHash $file -Algorithm SHA256).Hash

    $driverInfo = [PSCustomObject]@{
        Name = $file.Name
        BaseName = $file.BaseName
        Path = $file.FullName
        SizeKB = [math]::Round($file.Length / 1KB, 2)
        SHA256 = $hash
        Signed = $sig.Status -eq 'Valid'
        Signer = $sig.SignerCertificate.Subject -replace 'CN=|, O=.*', ''
        NotBefore = $sig.SignerCertificate.NotBefore
        NotAfter = $sig.SignerCertificate.NotAfter
        Loaded = $false
        DeviceExposed = $false
        DevicePath = $null
        Vendor = $null
    }

    # Vendor detection heuristic
    if ($driverInfo.Signer -match 'Microsoft') {
        $driverInfo.Vendor = 'Microsoft'
    } elseif ($driverInfo.Signer) {
        $driverInfo.Vendor = $driverInfo.Signer
    } else {
        $driverInfo.Vendor = 'Unsigned'
    }

    $results += $driverInfo
}

Write-Host "[*] Found $($results.Count) driver files"

# Phase 2: Correlate with loaded drivers
Write-Host "[*] Checking loaded drivers..."
$loadedDrivers = Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq 'Running'}

foreach ($loaded in $loadedDrivers) {
    $match = $results | Where-Object {$_.BaseName -eq $loaded.Name}
    if ($match) {
        $match.Loaded = $true
    }
}

$loadedCount = ($results | Where-Object {$_.Loaded}).Count
Write-Host "[*] $loadedCount drivers currently loaded"

# Phase 3: Probe for exposed device objects
Write-Host "[*] Probing for exposed device objects..."

$devicePrefixes = @(
    '\\.\'
)

# Common device naming patterns
$commonNames = $results | ForEach-Object {
    @(
        $_.BaseName,
        $_.BaseName.ToUpper(),
        $_.BaseName.ToLower(),
        ($_.BaseName -replace '\d+$', '')  # Strip trailing numbers
    )
} | Select-Object -Unique

foreach ($name in $commonNames) {
    $devicePath = "\\.\$name"
    try {
        $handle = [System.IO.File]::Open($devicePath, 'Open', 'Read', 'ReadWrite')
        $handle.Close()

        # Found exposed device
        $match = $results | Where-Object {
            $_.BaseName -eq $name -or
            $_.BaseName.ToUpper() -eq $name -or
            $_.BaseName.ToLower() -eq $name
        } | Select-Object -First 1

        if ($match) {
            $match.DeviceExposed = $true
            $match.DevicePath = $devicePath
            Write-Host "[+] EXPOSED: $devicePath ($($match.Name))"
        }
    } catch {
        # Not exposed or access denied (expected for most)
    }
}

$exposedCount = ($results | Where-Object {$_.DeviceExposed}).Count
Write-Host "[*] $exposedCount drivers expose device objects"

# Phase 4: Priority scoring
foreach ($driver in $results) {
    $score = 0

    # High priority: Third-party + loaded + exposed
    if ($driver.Vendor -ne 'Microsoft' -and $driver.Loaded -and $driver.DeviceExposed) {
        $score = 100
    }
    # Medium: Third-party + exposed (not loaded)
    elseif ($driver.Vendor -ne 'Microsoft' -and $driver.DeviceExposed) {
        $score = 80
    }
    # Medium: Third-party + loaded (no exposed device found yet)
    elseif ($driver.Vendor -ne 'Microsoft' -and $driver.Loaded) {
        $score = 60
    }
    # Low: Microsoft driver but exposed
    elseif ($driver.Vendor -eq 'Microsoft' -and $driver.DeviceExposed) {
        $score = 40
    }
    # Low: Third-party but not loaded
    elseif ($driver.Vendor -ne 'Microsoft') {
        $score = 20
    }

    $driver | Add-Member -NotePropertyName Priority -NotePropertyValue $score
}

# Export results
$outPath = "C:\bad\driver-inventory.json"
$results | ConvertTo-Json -Depth 10 | Out-File $outPath -Encoding UTF8

# Summary report
Write-Host "`n=== SUMMARY ==="
Write-Host "Total drivers: $($results.Count)"
Write-Host "Loaded: $loadedCount"
Write-Host "Exposed devices: $exposedCount"
Write-Host "Third-party: $(($results | Where-Object {$_.Vendor -ne 'Microsoft'}).Count)"
Write-Host "`nTop 10 targets (by priority):"
$results | Sort-Object -Property Priority -Descending | Select-Object -First 10 |
    Format-Table Name, Vendor, Priority, Loaded, DeviceExposed, DevicePath -AutoSize

Write-Host "`nFull results: $outPath"

# Also export high-priority targets as CSV for quick review
$highPri = $results | Where-Object {$_.Priority -ge 60} | Sort-Object -Property Priority -Descending
$highPri | Export-Csv "C:\bad\targets-high-priority.csv" -NoTypeInformation
Write-Host "High-priority targets: C:\bad\targets-high-priority.csv ($($highPri.Count) drivers)"
