# Driver enumeration script for winbox
# Finds all drivers and identifies high-priority BYOVD candidates

Write-Host "[*] Enumerating Windows drivers..."

# Get all driver files
$drivers = Get-ChildItem C:\Windows\System32\drivers\*.sys -ErrorAction SilentlyContinue

Write-Host "[*] Found $($drivers.Count) driver files"

# Get loaded drivers
$loadedDrivers = Get-CimInstance Win32_SystemDriver | Select-Object Name, PathName, State, Started

Write-Host "[*] Checking loaded status and device objects..."

$results = @()
foreach ($driver in $drivers) {
    $loaded = $loadedDrivers | Where-Object { $_.PathName -like "*$($driver.Name)*" }

    $result = [PSCustomObject]@{
        Name = $driver.Name
        Path = $driver.FullName
        SizeMB = [math]::Round($driver.Length / 1MB, 2)
        Loaded = ($null -ne $loaded)
        State = if ($loaded) { $loaded.State } else { "Not Loaded" }
        Signer = "Unknown"
    }
    $results += $result
}

# Export results
$outputPath = "C:\Windows\Temp\driver_enum.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "[+] Enumeration complete: $outputPath"
Write-Host "[*] Total drivers: $($drivers.Count)"
Write-Host "[*] Loaded drivers: $(($results | Where-Object { $_.Loaded }).Count)"

# Show top candidates (loaded, non-Microsoft)
Write-Host "`n[*] High-priority targets (loaded):"
$results | Where-Object { $_.Loaded } |
    Select-Object Name, SizeMB, State |
    Format-Table -AutoSize |
    Out-String |
    Write-Host
