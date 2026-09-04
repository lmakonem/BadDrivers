$ErrorActionPreference = "SilentlyContinue"
Write-Output "=== OS ==="
[System.Environment]::OSVersion.Version.ToString()
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
Write-Output "=== WHOAMI (priv) ==="
whoami
(whoami /priv | Select-String "SeDebugPrivilege")
Write-Output "=== DISK (free GB) ==="
[math]::Round((Get-PSDrive C).Free/1GB,1)
Write-Output "=== MSVC ==="
Write-Output ("msvc-root=" + (Test-Path "C:\Program Files\Microsoft Visual Studio"))
$vc = (Get-ChildItem "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter vcvars64.bat | Select -First 1).FullName
Write-Output ("cl=" + (Get-Command cl.exe).Source)
Write-Output "=== NET ==="
Write-Output ("aka.ms:443=" + (Test-NetConnection aka.ms -Port 443 -InformationLevel Quiet))
Write-Output ("github:443=" + (Test-NetConnection githubusercontent.com -Port 443 -InformationLevel Quiet))
Write-Output "=== FILES ==="
Write-Output ("PdFwKrnl=" + (Test-Path "C:\loldrivers\PdFwKrnl.sys"))
Write-Output ("warp.cpp=" + (Test-Path "C:\loldrivers\warp.cpp"))
Write-Output "=== LSASS ==="
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if($lsass){ Write-Output ("lsass-pid=" + $lsass.Id) } else { Write-Output "lsass=NOT FOUND" }
