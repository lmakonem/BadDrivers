# Win11 22H2 BYOVD Lab VM

## Prerequisites

### ISO needed — x86-64 Win11 22H2 (build 22621)

The existing ISO on this machine is **ARM64 Win11 26100** — that won't work because
the bigDrivers .sys files are x86-64 kernel drivers (ARM64 Windows won't load them).

Get the x86-64 evaluation ISO from Microsoft:
  https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
  (Select "ISO - 64-bit edition", 22H2 if available, else 23H2 is fine for the
   same EPROCESS offsets — cascade.cpp supports 22000–22621)

Alternatively use UUP dump (uupdump.net) to build a 22621 ISO directly.

After downloading, update `win11-lab.vmx`:
  ide1:0.fileName = "/path/to/your/Win11_22H2_x64.iso"

---

## Create the VMDK (once)

```bash
/Applications/VMware\ Fusion.app/Contents/Library/vmware-vdiskmanager \
  -c -s 80GB -a lsilogic -t 0 \
  "/Users/user/Virtual Machines.localized/Win11-22H2-BYOVD-Lab/Win11-22H2-BYOVD-Lab.vmdk"
```

Copy win11-lab.vmx into that same directory:
```bash
mkdir -p "/Users/user/Virtual Machines.localized/Win11-22H2-BYOVD-Lab"
cp win11-lab.vmx "/Users/user/Virtual Machines.localized/Win11-22H2-BYOVD-Lab/"
```

---

## Boot and Install

```bash
VMRUN=/Applications/VMware\ Fusion.app/Contents/Public/vmrun
VMX="/Users/user/Virtual Machines.localized/Win11-22H2-BYOVD-Lab/win11-lab.vmx"

$VMRUN start "$VMX" gui
```

Install Windows normally. Create a local Administrator account (skip Microsoft
account sign-in: use "Sign-in options → Domain join instead" on the account page).

---

## Post-install: disable HVCI, Credential Guard, PPL (run as Administrator in cmd.exe)

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f
shutdown /r /t 0
```

After reboot, confirm with:
```cmd
cascade.exe --check-security
```
Both `HVCI: DISABLED` and `Credential Guard: DISABLED` must show.

---

## Pre-flight probe

Copy `deploy/probe.ps1` into the VM and run:
```powershell
powershell -ep bypass -f probe.ps1
```
Must exit 0 (compatible) before running the BYOVD chain.

---

## Snapshots

Take a clean snapshot after post-install config before any driver loads:
```bash
$VMRUN snapshot "$VMX" "clean-post-config"
```

Revert between test runs:
```bash
$VMRUN revertToSnapshot "$VMX" "clean-post-config"
```

---

## Shared folder (macOS → VM)

To drop cascade.exe and the driver into the VM without a network share:
```bash
$VMRUN copyFileFromHostToGuest "$VMX" \
  /Users/user/repos/BadDrivers/BadDrivers/build/Release/cascade.exe \
  'C:\Users\Public\cascade.exe'
```
