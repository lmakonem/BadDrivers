# BadDrivers - Quick Start

Zero-day Windows driver vulnerability discovery on VM 125 (.210).

---

## What's Ready

✅ **Complete enumeration pipeline** - Scan drivers, identify exposed IOCTLs  
✅ **Analysis environment setup** - Test signing, WinDbg, Ghidra project  
✅ **Automated target fetching** - Pull high-priority drivers for reversing  
✅ **Comprehensive workflow** - Step-by-step from enum to exploit  
✅ **Existing BYOVD chain** - warp.exe ready to integrate new driver primitives  

---

## 5-Minute Start

```bash
cd /Users/lmakonem/repos/Research/BadDrivers

# 1. Configure VM (one-time: test signing + kernel debug)
./scripts/deploy-setup.sh
ssh root@192.168.36.225 'qm reboot 125'
sleep 60

# 2. Enumerate all drivers on .210
./scripts/run-enum.sh

# Output shows high-priority targets:
# 100 | ThirdPartyDriver.sys | VendorName | Loaded=True | Exposed=True | \\.\Device
```

That's it. You now have a prioritized list of drivers to analyze.

---

## Next: Static Analysis

```bash
# 3. Set up Ghidra project
cd ghidra
./init-project.sh

# 4. Fetch high-priority drivers from .210
./fetch-targets.sh

# 5. Open Ghidra and start hunting
open projects/BadDrivers.gpr
```

Then import a driver (File → Import) and follow the analysis checklist in **ghidra/README.md**.

---

## What You're Looking For

**High-value targets:**
- Third-party vendor drivers (not Microsoft-signed)
- Exposed device objects (`\\.\DeviceName`)
- Currently loaded (shows active use)

**Common vulnerabilities:**
1. **Missing size validation** on IOCTL buffers
2. **Arbitrary kernel read/write** primitives
3. **MSR/port I/O exposure** (physical memory access)
4. **METHOD_NEITHER** IOCTLs without ProbeForRead

---

## Full Workflow

See **VULN-DISCOVERY-WORKFLOW.md** for complete methodology:
- Ghidra analysis patterns
- WinDbg dynamic verification
- Exploit development
- Integration with warp.exe BYOVD chain

---

## File Map

| File | Purpose |
|------|---------|
| **scripts/deploy-setup.sh** | Configure .210 (test signing, kernel debug) |
| **scripts/run-enum.sh** | Enumerate drivers, export targets |
| **ghidra/init-project.sh** | Create Ghidra project |
| **ghidra/fetch-targets.sh** | Pull drivers from .210 |
| **VULN-DISCOVERY-WORKFLOW.md** | Complete step-by-step guide |
| **ghidra/README.md** | Ghidra analysis checklist |

---

## Expected Results

After enumeration, you'll see output like:

```
[*] Found 432 driver files
[*] 87 drivers currently loaded
[*] 12 drivers expose device objects
[*] 5 third-party drivers

Top 10 targets (by priority):
Priority  Name                    Vendor           Loaded  Exposed  DevicePath
100       SomeRGBDriver.sys       ThermaltakeCorp  True    True     \\.\SomeRGB
100       MonitorTool.sys         ASUSTeK          True    True     \\.\Monitor
80        OverclockDrv.sys        Gigabyte         False   True     \\.\OC
...
```

Focus on Priority 100 (third-party + loaded + exposed) first.

---

## Success Metrics

**You've found a zero-day when:**
- ✅ Ghidra shows missing validation in IOCTL handler
- ✅ WinDbg confirms exploitable behavior
- ✅ PoC code demonstrates kernel primitive
- ✅ (Bonus) Integrated with warp.exe for LSASS dump

---

## Questions?

- **"Where do I start?"** → Run `./scripts/deploy-setup.sh` then `./scripts/run-enum.sh`
- **"Which drivers to analyze?"** → Anything with Priority >= 80 in the output
- **"What tools do I need?"** → Ghidra (already installed), WinDbg (installed on .210 after setup)
- **"How long does this take?"** → Setup 10min, enum 5min, analysis varies (1hr-1day per driver)

---

Ready to hunt. Start with `./scripts/deploy-setup.sh`.
