# LockBit host-side emulation (F4) — drives detections H2 + H3

The LockBit host indicators were documented in prose but never wired into a build, so
`detections/elastic-sysmon.md` **H2** (anomalous named pipe) and **H3** (injection into
`wuauclt`) had no trigger. This binds them to concrete Apollo build parameters + one task each.
These are **existing agent config options**, not new tooling.

Apply on top of the **actor-attributed** ops build (DEPLOYMENT.md Phase 5b, LockBit profile).

## H3 — injection into `wuauclt.exe`  (Sysmon 8, CreateRemoteThread → wuauclt.exe)

1. **Set the sacrificial process to wuauclt** so fork&run post-ex lands in it. In the callback:
   ```
   spawnto_x64  C:\Windows\System32\wuauclt.exe
   spawnto_x86  C:\Windows\SysWOW64\wuauclt.exe
   ```
   (Apollo `spawnto` command / build default. Confirm exact syntax for your Apollo version.)
2. **Drive one fork&run task** so Apollo spawns `wuauclt` and injects into it:
   ```
   execute_assembly Seatbelt.exe -group=system
   ```
   This creates `wuauclt` and injects the assembly → a CreateRemoteThread into `wuauclt.exe`.

**Trigger / acceptance (H3):**
```
sequence by host.id with maxspan=1m
  [process where event.action == "CreateRemoteThread" and process.target.name == "wuauclt.exe"]  # Sysmon 8
  [network where event.action == "connection_attempted" and not process.code_signature.trusted]  # Sysmon 3
```
> Note on injection primitive: if your Apollo build injects via a primitive other than
> CreateRemoteThread (e.g. NtQueueApcThread), guarantee the Sysmon-8 event by injecting into an
> existing wuauclt PID with the explicit `inject <pid>` command, and/or broaden H3 to Sysmon 10
> (ProcessAccess) / 25 (ProcessTampering) targeting `wuauclt.exe`. Documented so the analytic and
> the emulation agree on the primitive.

## H2 — anomalous named pipe `fullduplex_84`  (Sysmon 17/18, PipeCreated/PipeConnected)

1. **Embed the SMB P2P profile** in the payload with the LockBit pipe name:
   ```
   C2 profile: smb
   pipename:   fullduplex_84
   ```
2. **Deploy a second Apollo as an SMB delegate** on an internal host and `link` to it:
   ```
   link <smb-agent-host-or-uuid>
   ```
   The SMB agent creates the named pipe `fullduplex_84` → Sysmon 17 PipeCreated (and 18 on connect).

**Trigger / acceptance (H2):**
```
file where event.action in ("PipeCreated","PipeConnected")   # Sysmon 17/18
  and file.name == "\\fullduplex_84"
```

## Acceptance summary

| Detection | Was firing on | Now fires on |
|---|---|---|
| **H3** (Sysmon 8, CreateRemoteThread → wuauclt) | nothing | spawnto=wuauclt + fork&run task |
| **H2** (Sysmon 17/18, pipe fullduplex_84) | nothing | smb profile pipename=fullduplex_84 + link |

Both were previously untested (generic `InjectionManager`, no pipe name set). Unit-test each with
Atomic Red Team (T1055 process injection; T1071 named-pipe atomics) before the full-chain run.
