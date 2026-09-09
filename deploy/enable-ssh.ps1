# enable-ssh.ps1 — run ONCE in the VM (elevated PowerShell) to enable SSH
# After this, snapshot the VM from Fusion (VM menu > Snapshots > Take Snapshot)
# or: sudo vmrun snapshot <vmx-path> "clean-baseline"
#
# Run: powershell -ep bypass -f enable-ssh.ps1

$ErrorActionPreference = 'Stop'

Write-Host "[*] Installing OpenSSH Server..." -ForegroundColor Cyan
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null

Write-Host "[*] Starting and auto-starting sshd..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

Write-Host "[*] Opening firewall port 22..." -ForegroundColor Cyan
$existing = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
if (-not $existing) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
        -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP `
        -Action Allow -LocalPort 22 | Out-Null
}

Write-Host "[*] Setting default shell to PowerShell..." -ForegroundColor Cyan
$pwshPath = (Get-Command powershell.exe).Source
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
    -Name DefaultShell -Value $pwshPath `
    -PropertyType String -Force | Out-Null

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } |
        Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "[+] SSH enabled. Connect from macOS:" -ForegroundColor Green
Write-Host "    ssh user@$ip" -ForegroundColor Yellow
Write-Host ""
Write-Host "    Then take snapshot:" -ForegroundColor Green
Write-Host "    sudo vmrun snapshot `"$env:USERPROFILE\..\..\..\baddrivers_vm.vmwarevm\baddrivers_vm.vmx`" clean-baseline" -ForegroundColor Yellow
