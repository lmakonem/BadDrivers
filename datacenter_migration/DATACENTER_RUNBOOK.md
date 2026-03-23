# iServices LLC - Datacenter Migration Runbook
## Meraki MX65 + MS120-8LP --> OPNsense NUC + Linksys LGS328C

**Organization**: iServices LLC (Meraki Org ID: 807950)
**Network**: iServices Network (Net ID: L_647955396387937125)
**Prepared by**: Automated migration tool
**Estimated downtime**: 15-30 minutes

---

## Pre-Migration Checklist (Before Leaving for DC)

- [ ] OPNsense installed on Intel NUC and tested
- [ ] OPNsense VLANs configured (1, 2, 100)
- [ ] OPNsense firewall rules in place (WAN access, inter-VLAN, VPN)
- [ ] OPNsense DHCP configured with static reservations for all iDRACs and hypervisors
- [ ] OPNsense WireGuard VPN configured and tested
- [ ] Linksys LGS328C VLANs configured (1, 2, 100)
- [ ] Linksys trunk port 25 configured (tagged 2,100 + untagged/native 1)
- [ ] Linksys access ports labeled and assigned to correct VLANs
- [ ] Linksys config saved to flash
- [ ] WireGuard client config on laptop (wireguard_howard.conf)
- [ ] This runbook printed or on phone
- [ ] Cable labels printed or tape + marker available
- [ ] SFP+ DAC cable for NUC-to-switch trunk (10G twinax)
- [ ] Console cable (just in case)
- [ ] Laptop with ethernet adapter

---

## Hardware Inventory - What You're Bringing

| Item | Purpose |
|------|---------|
| Intel NUC (4 NICs: 2x RJ45, 2x SFP+) | OPNsense firewall - replaces MX65 |
| Linksys LGS328C (24x RJ45 + 4x SFP+) | Managed switch - replaces MS120-8LP |
| SFP+ DAC cable (twinax) | 10G trunk link: NUC ixl0 <-> LGS328C port 25 |
| Ethernet cables (at least 2 spare) | In case existing cables are too short |
| USB flash drive | OPNsense installer (backup, just in case) |

---

## Current Datacenter Rack - What's There Now

### Meraki MX65 Firewall
- **Serial**: Q2QN-YN5U-4MRS
- **WAN1**: 216.66.77.183 (ISP cable in WAN1 port)
- **WAN2**: 216.66.77.184 (ISP cable in WAN2 port)
- **LAN Port 3**: Cable to MS120 switch port 1 (trunk)
- **LAN Ports 4-10**: Direct connections to VLAN 2 devices
- **LAN Ports 11-12**: Direct connections to VLAN 1 devices

### Meraki MS120-8LP Switch
- **Serial**: Q2BX-94DU-KXPU
- **Port 1**: Trunk uplink to MX65 port 3 (VLAN 1,10,20,30)
- **Port 2**: node02 iDRAC - 172.16.0.6, controller01 (node01 mgmt) - 172.16.0.29 (shared)
- **Port 3**: compute001 (node02 mgmt) - 172.16.0.41 (hosts 13+ VMs) + acirt01 (WRONG VLAN)
- **Port 4**: iservices01 (node03 mgmt) - 172.16.0.22
- **Port 5**: node03 iDRAC - 172.16.0.7 + ludus01 (WRONG VLAN) + ITSL-NAS (WRONG VLAN)
- **Port 6**: node01 iDRAC - 172.16.0.5
- **Port 7**: idrac-52XLK93 - 172.16.0.51 (NEW, undocumented)
- **Port 8**: idrac-532GK93 - 172.16.0.53 (NEW, undocumented)
- **Port 9-10**: Disabled (reserved for new servers)

**Note (2026-03-23):** Ports 7 and 8 now have different iDRACs than originally documented.
The "5th iDRAC" (node03-test, 172.16.0.8) and "client access" port are no longer present.
Two new Dell iDRACs (idrac-52XLK93 and idrac-532GK93) have appeared since the replug.

### Devices Connected to MX65 LAN Ports (VLAN 2)
- idrac-5DQQK93 - 192.168.38.160 (iDRAC for **ludus physical server**, will be reinstalled)
- cyberrange VM - 192.168.38.188 (VM on compute001, offline)
- grafana-loki-prometheus VM - 192.168.38.189 (VM on compute001, offline)
- vault-gitlab VM - 192.168.38.190 (VM on compute001, offline)
- taranis VM - 192.168.38.197 (undocumented Proxmox VM, online)

**Should be on MX65 LAN (VLAN 2) but currently on MS120 (VLAN 1) — WRONG:**
- ITSL-NAS (Synology) - 192.168.38.232 — currently on MS120 port 5
- acirt01 - 192.168.38.187 — currently on MS120 port 3
- ludus01 - 192.168.38.195 — currently on MS120 port 5

---

## Post-Replug Audit — 2026-03-20 (Meraki API Verification)

After unplugging and replugging the Meraki equipment, an API audit revealed multiple
cabling errors on the MS120-8LP and missing devices. Both the MX65 and MS120 are online.
WAN1 (216.66.77.183) and WAN2 (216.66.77.184) are both active.

### Check — 2026-03-21 ~03:30 UTC

#### MX65 Uplinks — OK
- **WAN1**: active — 216.66.77.183 (static)
- **WAN2**: active — 216.66.77.184 (static)

#### MS120 Port Status (live 60s)

| Port | Link | Clients | LLDP |
|------|------|---------|------|
| 1 | Connected | 1 | Meraki MX65 (trunk) |
| 2 | Connected | 1 | — |
| 3 | Connected | 1 | Meraki MX65 |
| 4 | Connected | 0 | — (100 Mbps) |
| 5 | Connected | 0 | 34:80:0d:bf:36:10 |
| 6 | Connected | 1 | — |
| 7 | Disconnected | 0 | 34:80:0d:bf:36:10 |
| 8 | Connected | 1 | — |
| 9-10 | Disabled | 0 | — |

---

### Latest Check — 2026-03-23 ~14:00 UTC (Meraki API + VPN Ping)

#### MX65 Uplinks — OK
- **WAN1**: active — 216.66.77.183 (static)
- **WAN2**: active — 216.66.77.184 (static)

#### MS120 Actual Port Map (from Meraki client API, 30-day window)

| Port | Devices (MAC / Description) | Meraki IP | Documented IP | Status | Notes |
|------|----------------------------|-----------|---------------|--------|-------|
| 1 | MX65 trunk (`0c:8d:db:ae:19:d5`) | — | — | Connected | Trunk uplink, correct |
| 2 | `44:a8:42:15:2a:70` node02 iDRAC | 172.16.0.6 | 172.16.0.6 | **Online** | IP matches |
|   | `2c:ea:7f:fc:db:2a` idrac-5DQQK93 | 172.16.0.86 | 192.168.38.160 | Offline (on this port) | **MOVED** — see note below |
|   | `24:6e:96:5f:37:5c` controller01 | 172.16.0.29 | 172.16.0.29 | **Offline** | IP matches, server is down |
| 3 | `ec:f4:bb:d5:2a:d4` compute001 | 172.16.0.41 | 172.16.0.41 | **Offline** | IP matches, server is down |
|   | `00:10:18:f6:45:9b` acirt01 | 192.168.38.187 | 192.168.38.187 | **Online** | IP matches but **WRONG VLAN** (on VLAN 1 port) |
|   | `bc:24:11:2b:3c:66` taranis (Proxmox VM) | 172.16.0.4 | *not documented* | **Online** | VM on compute001, undocumented |
|   | Multiple compute001 VMs (see below) | various .0.x IPs | *not documented* | Offline | VMs on compute001 |
| 4 | `ec:f4:bb:d3:04:a8` iservices01 | 172.16.0.22 | 172.16.0.22 | **Offline** | IP matches, server is down. Use iDRAC at 172.16.0.7 to power on |
|   | `24:6e:96:5f:37:5d` (Dell 2nd NIC) | — | *not documented* | Offline | Likely controller01 2nd NIC (MAC is +1 from controller01) |
| 5 | `44:a8:42:03:c1:48` node03 iDRAC | 172.16.0.7 | 172.16.0.7 | **Online** | IP matches. **This is iservices01's iDRAC** |
|   | `34:80:0d:bf:36:00` ludus01 | 192.168.38.195 | 192.168.38.195 | **Online** | IP matches but **WRONG VLAN** (on VLAN 1 port) |
|   | `00:11:32:e9:1f:c7` ITSL-NAS (NIC 1) | 192.168.38.232 | 192.168.38.232 | Offline | **WRONG VLAN** (on VLAN 1 port) |
|   | `00:11:32:e9:1f:c8` ITSL-NAS (NIC 2) | 172.16.0.83 | *not documented* | Offline | Synology 2nd NIC, undocumented |
| 6 | `18:66:da:9f:0d:0d` node01 iDRAC | 172.16.0.5 | 172.16.0.5 | **Online** | IP matches |
| 7 | `2c:ea:7f:fc:e2:74` idrac-52XLK93 | 172.16.0.51 | *not documented* | **Online** | **NEW** — undocumented Dell iDRAC |
| 8 | `2c:ea:7f:fc:d3:98` idrac-532GK93 | 172.16.0.53 | *not documented* | **Online** | **NEW** — undocumented Dell iDRAC |

#### VMs on compute001 (MS120 port 3, all Proxmox VMs — offline since compute001 is down)

| MAC | Description | Meraki IP | Status |
|-----|-------------|-----------|--------|
| `bc:24:11:71:22:b9` | securityonion | 172.16.0.51 | Offline |
| `bc:24:11:0b:42:d3` | SIEM-Data | 172.16.0.83 | Offline |
| `bc:24:11:34:ae:c0` | SIEM-CoPilot-Detect | 172.16.0.53 | Offline |
| `bc:24:11:59:88:eb` | SIEM-CoPilot-Mgmt | 172.16.0.86 | Offline |
| `bc:24:11:1d:a7:ae` | ubuntu2204 | 172.16.0.56 | Offline |
| `bc:24:11:a4:51:51` | openclaw | 172.16.0.82 | Offline |
| `bc:24:11:20:3c:b1` | swordphish | 172.16.0.42 | Offline |
| `bc:24:11:8d:35:c5` | zabbix | 172.16.0.46 | Offline |
| `bc:24:11:6b:4b:44` | k3s-01 | 172.16.0.206 | Offline |
| `bc:24:11:07:0b:fa` | k8supervisor | 172.16.0.209 | Offline |
| `bc:24:11:6a:a1:df` | WIN11-22H2-X64 | 172.16.0.212 | Offline |
| `bc:24:11:81:68:85` | debian12 | 172.16.0.68 | Offline |
| `bc:24:11:2e:6d:b8` | WIN-LKQOJ7A2DQC | 172.16.0.84 | Offline |

#### Devices on MX65 LAN ports (VLAN 2)

| MAC | Description | Meraki IP | Documented IP | Status | Notes |
|-----|-------------|-----------|---------------|--------|-------|
| `bc:24:11:c0:bd:5b` | cyberrange VM | 192.168.38.188 | 192.168.38.188 | Offline | VM on compute001 |
| `bc:24:11:49:62:af` | grafana-loki-prometheus VM | 192.168.38.189 | 192.168.38.189 | Offline | VM on compute001 |
| `bc:24:11:e7:04:95` | vault-gitlab VM | 192.168.38.190 | 192.168.38.190 | Offline | VM on compute001 |
| `bc:24:11:2b:3c:66` | taranis (Proxmox VM) | 192.168.38.197 | *not documented* | **Online** | Undocumented VM, has both VLAN 1+2 IPs |

#### VPN Clients (via MX65 AnyConnect/Client VPN)

| MAC | User | IP | Status |
|-----|------|----|--------|
| `03:8a:be:2d:57:b0` | hmukanda@gmail.com | 172.17.1.217 | Online |
| `03:3a:bf:10:5c:e5` | kouassi.azagba@iservices.africa | 10.10.10.75 | Online |
| `03:3c:bd:c0:40:89` | ezeckiel.dadjo@iservices.africa | 10.10.10.23 | Online |
| `03:06:96:9f:4d:ab` | soultone.wassi@iservices.africa | 10.10.10.132 | Offline |

#### VPN Ping + HTTPS Reachability Test (2026-03-23)

| Device | IP | Ping | HTTPS | Status |
|--------|-----|------|-------|--------|
| OPNsense GW (VLAN 1) | 172.16.0.1 | OK | — | UP (Meraki is GW, not OPNsense yet) |
| OPNsense GW (VLAN 2) | 192.168.38.1 | OK | — | UP |
| node01 iDRAC | 172.16.0.5 | OK | 302 | **UP** |
| node02 iDRAC | 172.16.0.6 | OK | 302 | **UP** |
| node03 iDRAC | 172.16.0.7 | OK | 302 | **UP** |
| node03-test iDRAC | 172.16.0.8 | FAIL | — | **DOWN** |
| iservices01 | 172.16.0.22 | FAIL | — | **DOWN** — use iDRAC at 172.16.0.7 to power on |
| controller01 | 172.16.0.29 | FAIL | — | **DOWN** |
| compute001 | 172.16.0.41 | FAIL | — | **DOWN** |
| idrac-5DQQK93 | 192.168.38.160 | OK | 302 | **UP** — this is the ludus server iDRAC (https://192.168.38.160/restgui/) |
| acirt01 | 192.168.38.187 | OK | — | **UP** — still on WRONG VLAN (MS120 port 3) |
| ludus01 | 192.168.38.195 | FAIL | — | **DOWN** — still on WRONG VLAN (MS120 port 5) |
| ITSL-NAS | 192.168.38.232 | FAIL | — | **DOWN** |

**7 UP** (4 iDRACs, 2 gateways, acirt01) | **6 DOWN** (3 servers, node03-test iDRAC, ludus01, ITSL-NAS)

#### Key Findings & Corrected Topology — 2026-03-23

##### Physical Server to iDRAC/NIC Mapping (confirmed via Redfish)

| Physical Server | ServiceTag | iDRAC MAC           | iDRAC IP       | OS NIC MAC                 | OS Hostname          | OS IP          |
| --------------- | ---------- | ------------------- | -------------- | -------------------------- | -------------------- | -------------- |
| node01 (R730)   | G875KH2    | `18:66:da:9f:0d:0d` | 172.16.0.5     | `24:6E:96:5F:37:5C` (NIC3) | controller01         | 172.16.0.29    |
| node02 (R730)   | 4ZCX942    | `44:A8:42:15:2A:70` | 172.16.0.6     | `EC:F4:BB:D3:04:A8` (NIC1) | iservices01          | 172.16.0.22    |
| node03 (R730)   | 7Y1KB42    | `44:A8:42:03:C1:48` | 172.16.0.7     | `EC:F4:BB:D5:2A:D4` (NIC3) | compute001 (Proxmox) | 172.16.0.41    |
| ludus (R640)    | 5DQQK93    | `2C:EA:7F:FC:DB:2A` | 192.168.38.160 | `34:80:0D:BF:36:00`        | ludus01              | 192.168.38.195 |

**Note:** iDRACs and OS NICs are on **separate physical interfaces** with separate cables.
The iDRAC hostname in Redfish does NOT match the OS hostname. Node03's iDRAC says "esxi02"
but the OS running on it is Proxmox (compute001 at 172.16.0.41 hosting VMs including VM 801).

##### Current MX65 Port Assignments (after cable move + fixes)

| MX65 Port | Type | VLAN | Devices | Status |
|-----------|------|------|---------|--------|
| 3 | access | 1 | MS120 trunk uplink | OK |
| **4** | **access** | **2** | **ludus01 OS (192.168.38.195) + acirt01 (192.168.38.187)** | **PROTECTED — DO NOT TOUCH** |
| 5 | access | 2 | idrac-5DQQK93 or acirt01 (one of these ports) | OK |
| **6** | **trunk** | **1 native, all** | **compute001 OS (172.16.0.41) + iDRAC .7 (172.16.0.7)** | **PROTECTED — DO NOT TOUCH** |
| 7 | access | 2 | idrac-5DQQK93 or acirt01 (one of these ports) | OK |
| **8** | **trunk** | **1 native, all** | **iservices01 OS (172.16.0.22)** | **PROTECTED — DO NOT TOUCH** |
| 9 | access | 2 | (empty) | |
| 10 | access | 2 | (empty) | |
| 11 | access | 1 | (available) | |
| 12 | access | 1 | (available) | |

> **CRITICAL: PROTECTED PORTS — DO NOT MODIFY**
>
> **MX65 Port 4:** ludus01 Proxmox (192.168.38.195) and acirt01 (192.168.38.187).
> Access VLAN 2. Static IP on ludus01 via /etc/network/interfaces.
> Docker bridge 172.17.0.0/16 overlaps with Meraki VPN 172.17.1.0/24 —
> route added: `172.17.1.0/24 via 192.168.38.1` in /etc/network/interfaces.
>
> **MX65 Port 6:** compute001 (172.16.0.41) and iDRAC .7 (172.16.0.7).
> Trunk, native VLAN 1. Any change will bring down the Proxmox hypervisor and all its VMs.
>
> **MX65 Port 8:** iservices01 (172.16.0.22). Trunk, native VLAN 1. Static IP via netplan.
> Docker bridge 172.17.0.0/16 overlaps with Meraki VPN subnet 172.17.1.0/24 —
> route added: `172.17.1.0/24 via 172.16.0.1` in /etc/netplan/01-netcfg.yaml.
>
> **MX65 Ports 5, 7, 9, 10:** Access VLAN 2. idrac-5DQQK93 (192.168.38.160)
> and acirt01 (192.168.38.187) are on two of these ports. All confirmed working.
>
> **MS120 Ports 2, 6, 7, 8:** iDRACs — do not change VLAN or disable.

##### Current MS120 Port Assignments

| MS120 Port | Type | VLAN | Devices | Status |
|------------|------|------|---------|--------|
| 1 | trunk | 1 native, all | MX65 uplink | OK |
| 2 | access | 1 | node02 iDRAC (172.16.0.6) | Online |
| 3 | trunk | 1 native, all | compute001 OS NIC (NOT active here — OS NIC is on MX65 port 6) | Link up, 0 clients |
| 4 | access | 1 | iservices01 2nd NIC? (100 Mbps link, 0 clients) | |
| 5 | access | 1 | Disconnected | |
| 6 | access | 1 | node01 iDRAC (172.16.0.5) | Online |
| 7 | access | 1 | idrac-52XLK93 (172.16.0.51) | Online |
| 8 | access | 1 | idrac-532GK93 (172.16.0.53) | Online |
| 9-10 | access | 1 | Disabled | |

##### Findings

1. **compute001** (172.16.0.41, Proxmox hosting VM 801 and 13+ VMs) runs on the physical
   server with iDRAC .7 (node03, ServiceTag 7Y1KB42). Its OS NIC (`EC:F4:BB:D5:2A:D4`)
   and iDRAC (`44:A8:42:03:C1:48`) are both cabled to **MX65 port 6** (trunk, native VLAN 1).
   **CONFIRMED WORKING** — https://172.16.0.41:8006 returns HTTP 200.
2. **iDRAC .7** (172.16.0.7, static IP) is on **MX65 port 6**. **CONFIRMED WORKING.**
3. **idrac-5DQQK93** (`2c:ea:7f:fc:db:2a`) at 192.168.38.160 is the iDRAC for the
   **ludus physical server** (R640, ServiceTag 5DQQK93). Also on MX65 port 6.
   Currently **unreachable** because port 6 native VLAN is 1 and this iDRAC has a
   VLAN 2 static IP. The ludus01 OS will be **reinstalled**.
4. **iservices01** (`ec:f4:bb:d3:04:a8`) is on **MX65 port 8** (trunk, native VLAN 1).
   Its physical server is node02 (iDRAC .6 at 172.16.0.6, on MS120 port 2).
   **CONFIRMED WORKING** at 172.16.0.22 — static IP set via netplan, with a specific
   route for 172.17.1.0/24 to avoid conflict with Docker bridge (172.17.0.0/16).
   The OS is Ubuntu 6.8.0 running Docker containers (not Proxmox). Interface is `eno1`.
5. **Two undocumented iDRACs** on MS120:
   - **idrac-52XLK93** (`2c:ea:7f:fc:e2:74`) at 172.16.0.51 on MS120 port 7
   - **idrac-532GK93** (`2c:ea:7f:fc:d3:98`) at 172.16.0.53 on MS120 port 8
6. **acirt01** is on MX65 port 4 (shared with iservices01 via unmanaged switch).
7. **ITSL-NAS**, **ludus01** — locations need confirmation, currently unreachable.
8. **taranis** (`bc:24:11:2b:3c:66`) is an undocumented Proxmox VM, currently online.

### Completed Fixes

| Device | IP | MX65/MS120 Port | Fix Applied | Status |
|--------|-----|----------------|-------------|--------|
| compute001 (Proxmox) | 172.16.0.41 | MX65 port 6 (trunk) | Port set to trunk native VLAN 1, force restarted via iDRAC .7 | **WORKING — PROTECTED** |
| iDRAC .7 (node03) | 172.16.0.7 | MX65 port 6 (trunk) | Same port as compute001, static IP | **WORKING — PROTECTED** |
| iservices01 (Docker) | 172.16.0.22 | MX65 port 8 (trunk) | Port set to trunk native VLAN 1, static IP via netplan, added route for 172.17.1.0/24 to fix Docker bridge overlap | **WORKING — PROTECTED** |
| ludus01 (Proxmox) | 192.168.38.195 | MX65 port 4 (access VLAN 2) | Port set to access VLAN 2, static IP in /etc/network/interfaces, added route for 172.17.1.0/24 via 192.168.38.1 to fix Docker bridge overlap | **WORKING — PROTECTED** |
| idrac-5DQQK93 (ludus iDRAC) | 192.168.38.160 | MX65 port 5 or 7 (access VLAN 2) | Ports restored to access VLAN 2 (were stuck in trunk mode) | **WORKING** |
| acirt01 | 192.168.38.187 | MX65 port 4 or 5/7 (access VLAN 2) | Ports restored to access VLAN 2 | **WORKING** |

### Remaining Fixes (Next Session)

| Step | Priority | Action | Notes |
|------|----------|--------|-------|
| 1 | **HIGH** | **Reinstall controller01** (172.16.0.29) | **MARKED FOR REINSTALL.** Physical server: node01 (R730, G875KH2, iDRAC .5 at https://172.16.0.5). OS is an OpenStack controller (OpenVSwitch, VRRP/keepalived, multiple VIPs .29/.245/.246). OS is UP and accessible via iDRAC console (user `user`, has venv). NIC3 (`24:6E:96:5F:37:5C`) on MS120 port 3, VLAN 1. NIC4 (`:5D`) on MS120 port 4, VLAN 1. **Problem:** Server sends ARP for 172.16.0.1 but gets no reply. VRRP (vrid 51) is broadcasting on the VLAN. Meraki may be blocking due to VRRP/ARP conflict. Server receives broadcasts from MX65 but MX65 won't reply to its ARP. Stopping VRRP/keepalived and removing extra IPs (.245, .246) may fix connectivity, but server is marked for reinstall instead. iDRAC SSH: `sshpass -p Lahilabs2018 ssh root@172.16.0.5`. |
| 2 | **HIGH** | **ITSL-NAS** (192.168.38.232) — **NEEDS PHYSICAL ACCESS** | NAS is powered on but has NO link on any Meraki port. Both NICs (`00:11:32:e9:1f:c7` and `:c8`) last seen on MS120 port 5 on 2026-03-21, port is now disconnected. Cable may be unplugged, broken, or in a dead port. Needs physical trace and replug at the rack into an MX65 VLAN 2 port (5, 7, 9, or 10). |
| 3 | **MED** | Start **cyberrange VM** on ludus01 | Via Proxmox UI at https://192.168.38.195:8006 — cyberrange (MAC `bc:24:11:c0:bd:5b`) is a VM on the ludus Proxmox server, expected IP 192.168.38.188 on VLAN 2. |
| 4 | **MED** | Start other VMs on compute001 | Via Proxmox UI at https://172.16.0.41:8006 — grafana-loki (.189), vault-gitlab (.190), etc. Note: compute001 is on MX65 port 6 (trunk native VLAN 1). VMs needing VLAN 2 must have VLAN tagging configured in Proxmox bridge. |
| 5 | **LOW** | Add DHCP reservations on Meraki VLAN 1 | For idrac-52XLK93 (.51), idrac-532GK93 (.53). Already added for compute001 (.41), iservices01 (.22), controller01 (.29). |
| 6 | **LOW** | Make iservices01 IP persistent | Already done — netplan config at `/etc/netplan/01-netcfg.yaml` with static IP 172.16.0.22 and route for 172.17.1.0/24. Verified. |
| 7 | **LOW** | Make ludus01 route persistent | Already done — `/etc/network/interfaces` has `post-up ip route add 172.17.1.0/24 via 192.168.38.1`. Verified. |

### Known Issues

1. **Docker bridge overlap on all servers**: Docker creates `172.17.0.0/16` bridge which
   overlaps with Meraki VPN subnet `172.17.1.0/24`. Every server running Docker needs a
   specific route: `172.17.1.0/24 via <gateway>`. Fixed on iservices01 and ludus01.
   Controller01 likely has the same issue.

2. **idrac-5DQQK93** (192.168.38.160) is the ludus server iDRAC. It's on one of MX65
   ports 5, 7, 9, or 10 (all access VLAN 2). Currently working. The exact port is not
   confirmed — do not change ports 5, 7, 9, 10 without checking impact on this iDRAC.

3. **MS120 ports 3 and 4** have link (1 Gbps and 100 Mbps) but no identified clients.
   Port 3 may be a leftover cable from compute001's old position. Port 4 may be
   controller01's NIC4 (`:5D`, 100 Mbps matches). Needs confirmation.

**After fixes, verify all clients are online via Meraki API or VPN ping test.**

### Final State — 2026-03-23 ~17:20 UTC

| Device                | IP             | Ping     | Location            | Status                                                      |
| --------------------- | -------------- | -------- | ------------------- | ----------------------------------------------------------- |
| MX65 gateway (VLAN 1) | 172.16.0.1     | UP       | —                   | OK                                                          |
| MX65 gateway (VLAN 2) | 192.168.38.1   | UP       | —                   | OK                                                          |
| node01 iDRAC          | 172.16.0.5     | UP       | MS120 port 6        | OK                                                          |
| node02 iDRAC          | 172.16.0.6     | UP       | MS120 port 2        | OK                                                          |
| node03 iDRAC          | 172.16.0.7     | UP       | MX65 port 6         | OK — PROTECTED                                              |
| iservices01           | 172.16.0.22    | UP       | MX65 port 8         | OK — PROTECTED, static IP via netplan                       |
| controller01          | 172.16.0.29    | **DOWN** | MX65 port (unknown) | Server ON, NIC has link, wrong IP (.245), needs console fix |
| compute001            | 172.16.0.41    | UP       | MX65 port 6         | OK — PROTECTED, Proxmox HTTP 200                            |
| idrac-52XLK93         | 172.16.0.51    | UP       | MS120 port 7        | OK                                                          |
| idrac-532GK93         | 172.16.0.53    | UP       | MS120 port 8        | OK                                                          |
| idrac-5DQQK93         | 192.168.38.160 | UP       | MX65 port 5/7/9/10  | OK — ludus iDRAC                                            |
| acirt01               | 192.168.38.187 | UP       | MX65 port 4 or 5/7  | OK                                                          |
| ludus01               | 192.168.38.195 | UP       | MX65 port 4         | OK — PROTECTED, Proxmox HTTP 200                            |
| ITSL-NAS              | 192.168.38.232 | **DOWN** | No link anywhere    | Powered on, cable disconnected                              |

**12 UP / 2 DOWN**

---

## New Equipment - Port Mapping

### OPNsense NUC Interfaces
| Interface | Type | Role | IP / Config |
|-----------|------|------|-------------|
| igc0 | RJ45 2.5G | WAN | DHCP from ISP (will get 216.66.77.183) |
| ixl0 | SFP+ 10G | LAN trunk | No IP (VLAN trunk parent) |
| ixl1 | SFP+ 10G | WAN2 | DHCP (will get 216.66.77.184) |
| igc1 | RJ45 (if exists) | Spare | Not used |

### Linksys LGS328C Port Map
| Port          | Device                     | VLAN                       | Mode              | Expected IP    |
| ------------- | -------------------------- | -------------------------- | ----------------- | -------------- |
| 1             | controller01 (node01 mgmt) | 1                          | Access (untagged) | 172.16.0.29    |
| 2             | compute001 (node02 mgmt)   | 1                          | Access (untagged) | 172.16.0.41    |
| 3             | iservices01 (node03 mgmt)  | 1                          | Access (untagged) | 172.16.0.22    |
| 4             | node01 iDRAC               | 1                          | Access (untagged) | 172.16.0.5     |
| 5             | node02 iDRAC               | 1                          | Access (untagged) | 172.16.0.6     |
| 6             | node03 iDRAC               | 1                          | Access (untagged) | 172.16.0.7     |
| 7             | idrac-52XLK93              | 1                          | Access (untagged) | 172.16.0.51    |
| 8             | idrac-532GK93              | 1                          | Access (untagged) | 172.16.0.53    |
| 9             | ITSL-NAS                   | 2                          | Access (untagged) | 192.168.38.232 |
| 10            | acirt01                    | 2                          | Access (untagged) | 192.168.38.187 |
| 11            | ludus01                    | 2                          | Access (untagged) | 192.168.38.195 |
| 12            | idrac-5DQQK93 (ludus iDRAC)| 2                          | Access (untagged) | 192.168.38.160 |
| 13            | VLAN2 spare                | 2                          | Access (untagged) | DHCP           |
| 14-24         | Available                  | 1                          | Access (untagged) | —              |
| **25 (SFP+)** | **OPNsense NUC**           | **1 native, 2+100 tagged** | **Trunk**         | —              |
| 26-28         | Available                  | 1                          | Access (untagged) | —              |

### VLAN Summary
| VLAN ID | Name         | Subnet          | Gateway       | DHCP Range | Purpose                            |
| ------- | ------------ | --------------- | ------------- | ---------- | ---------------------------------- |
| 1       | Kypo         | 172.16.0.0/24   | 172.16.0.1    | .100-.250  | Server mgmt, iDRACs, Proxmox hosts |
| 2       | DetectionLab | 192.168.38.0/24 | 192.168.38.1  | .51-.250   | NAS, detection lab servers         |
| 100     | iSCSI        | 192.168.1.0/24  | 192.168.1.254 | .100-.250  | Storage traffic                    |

---

## Migration Procedure - Step by Step

### Phase 1: Preparation at the Rack (5 min)

1. **Photograph everything**
   - Take photos of every cable on the MX65 (front and back)
   - Take photos of every cable on the MS120 (front and back)
   - Take photos of rack layout
   - Note which ISP cables go to WAN1 and WAN2

2. **Label every cable**
   - Label each cable at both ends before unplugging anything
   - Use the port map above as reference

3. **Verify current connectivity**
   - Log into Meraki Dashboard on your phone
   - Confirm all devices show as online
   - Note any devices that are already offline

### Phase 2: Rack New Equipment (5 min)

4. **Rack the Linksys LGS328C**
   - Mount in the rack (ideally near where the MS120 is)
   - DO NOT connect any cables yet

5. **Rack the Intel NUC**
   - Mount in the rack (ideally near the switch)
   - DO NOT power on yet
   - Connect power cable but leave it off

6. **Connect the trunk cable**
   - Plug the SFP+ DAC cable between:
     - NUC port: **ixl0** (one of the SFP+ ports)
     - Switch port: **25** (first SFP+ port on the LGS328C)

### Phase 3: Cable Migration (10 min)

**IMPORTANT**: Move cables one at a time to avoid confusion.

7. **Move WAN cables from MX65 to NUC**
   - Unplug WAN1 cable from MX65 --> plug into NUC **igc0** (RJ45)
   - Unplug WAN2 cable from MX65 --> plug into NUC **ixl1** (second SFP+, or second RJ45 if available)
   - If WAN2 is RJ45 and NUC only has one RJ45, you may need a media converter or skip dual-WAN for now

8. **Move VLAN 1 server cables from MS120 to LGS328C**

   | Old MS120 Port | Cable Label | New LGS328C Port |
   |----------------|-------------|-------------------|
   | 2 | controller01 (node01) | **1** |
   | 3 | compute001 (node02) | **2** |
   | 4 | iservices01 (node03) | **3** |
   | 7 | node01 iDRAC | **4** |
   | 6 | node02 iDRAC | **5** |
   | 5 | node03 iDRAC | **6** |
   | 8 | Dell test/spare | **7** |

9. **Move VLAN 2 device cables from MX65 LAN ports to LGS328C**

   | Old MX65 Port | Cable Label | New LGS328C Port |
   |---------------|-------------|-------------------|
   | LAN 4-10 (find ITSL-NAS) | ITSL-NAS | **8** |
   | LAN 4-10 (find acirt01) | acirt01 | **9** |
   | LAN 4-10 (find ludus01) | ludus01 | **10** |
   | LAN 4-10 (find idrac-5DQQK93) | idrac-5DQQK93 | **11** |
   | Remaining MX65 LAN cables | VLAN2 devices | **12-13** |

### Phase 4: Power On and Verify (5-10 min)

10. **Power on the NUC**
    - Wait 2-3 minutes for OPNsense to boot fully
    - The console should show WAN IP (216.66.77.183 via DHCP)

11. **Verify WAN connectivity**
    - From your phone: try to browse the internet through the DC network
    - OR: connect your laptop to any VLAN 1 port (14-24) and test

12. **Verify WireGuard VPN**
    - On your laptop, activate the WireGuard tunnel
    - The endpoint is `216.66.77.183:51820`
    - Try pinging `172.16.0.1` (OPNsense VLAN 1 gateway)

13. **Verify servers are getting IPs**
    - Check OPNsense DHCP leases: https://216.66.77.183 > Services > Dnsmasq > DHCP Leases
    - Or via SSH: `cat /var/db/dnsmasq.leases`
    - Each server should pick up its reserved IP within 1-2 minutes

14. **Verify inter-VLAN routing**
    - From a VLAN 1 device, ping a VLAN 2 device (e.g., ping 192.168.38.232 from 172.16.0.29)

15. **Verify port forwarding**
    - From outside: test port 8843 to WAN2 (216.66.77.184) reaching 192.168.38.8:443

16. **Verify iDRAC access**
    - Via WireGuard VPN, browse to:
      - https://172.16.0.5 (node01 iDRAC)
      - https://172.16.0.6 (node02 iDRAC)
      - https://172.16.0.7 (node03 iDRAC)

### Phase 5: Cleanup (5 min)

17. **Power down Meraki equipment**
    - Power off the MX65
    - Power off the MS120-8LP
    - DO NOT remove them from the rack yet - keep as rollback option for 48 hours

18. **Verify everything is stable**
    - Monitor for 15-30 minutes
    - Check OPNsense dashboard for errors
    - Check that all DHCP leases are assigned
    - Check WireGuard VPN stays connected

19. **Update DNS / monitoring**
    - Update any DNS records that point to the old WAN IPs (if applicable)
    - Update monitoring systems to point to OPNsense
    - Update syslog destination if needed (was 172.16.0.53:514)

---

## Rollback Procedure

If something goes critically wrong and you need to revert:

### Quick Rollback (2 min)

1. Power off the NUC
2. Power off the LGS328C
3. Move all cables back to original Meraki ports (use your photos!)
4. Power on the MX65 and MS120
5. Wait 3-5 minutes for Meraki to re-sync with the cloud
6. Everything should come back as before (Meraki config is in the cloud)

### Key Points
- Meraki config is cloud-managed - it doesn't change when the devices are offline
- The MX65 and MS120 will resume exactly where they left off
- Keep Meraki devices in the rack (unpowered but cabled-ready) for at least 48 hours
- After 48 hours of stable operation, you can remove the Meraki gear

---

## Post-Migration Tasks

- [ ] Monitor OPNsense logs for 24-48 hours
- [ ] Verify all VPN users can connect via WireGuard
- [ ] Set up OPNsense config backup (System > Configuration > Backups)
- [ ] Configure Suricata IDS/IPS if needed
- [ ] Remove old Meraki equipment from rack after 48 hours stable
- [ ] Cancel Meraki license subscription (saves $$$)
- [ ] Update network documentation

---

## Emergency Contacts & Access

| System | Access | Credentials |
|--------|--------|-------------|
| OPNsense Web GUI | https://216.66.77.183 (or WAN IP) | root / lahilabs2018 |
| OPNsense SSH | ssh root@216.66.77.183 | root / lahilabs2018 |
| Linksys Switch | http://172.16.0.251 (via VPN) | admin / lahilabs2018 |
| WireGuard VPN | 216.66.77.183:51820 | wireguard_howard.conf |
| Meraki Dashboard | dashboard.meraki.com | hmukanda@gmail.com |

---

## Network Diagram

```
                         INTERNET
                            |
                     [ ISP Router/Handoff ]
                       |            |
                    WAN1          WAN2
                  (RJ45)        (RJ45/SFP+)
                       |            |
                  +----+----+-------+
                  | OPNsense NUC    |
                  | igc0=WAN1       |
                  | ixl1=WAN2       |
                  | ixl0=LAN trunk  |
                  +---------+-------+
                            |
                      10G SFP+ DAC
                       (VLAN trunk)
                      1U, 2T, 100T
                            |
                  +---------+----------+
                  | Linksys LGS328C    |
                  | Port 25 (SFP+)     |
                  +----+-------+-------+
                       |       |
              Ports 1-7    Ports 8-13
              VLAN 1       VLAN 2
              172.16.0.x   192.168.38.x
                  |            |
          +-------+------+    +--------+-------+
          |       |      |    |        |       |
       node01  node02  node03 NAS   acirt01  ludus01
       .29     .41     .22    .232   .187    .195
          |       |      |
       iDRAC  iDRAC  iDRAC
       .5     .6     .7

    VPN Clients (WireGuard)
    10.10.10.0/24
    --> Can reach all VLANs
```

---

## Site-to-Site VPN (IPsec) - To Configure Post-Migration

From Meraki export, there was an IPsec tunnel:
- **Peer**: 184.105.196.26
- **PSK**: 10coatwhenrub29famoussubject995167
- **Remote subnets**: 192.168.1.0/24, 192.168.2.0/24
- **Phase 1**: IKEv1, AES128, SHA1, DH Group 2, 3600s
- **Phase 2**: AES128, SHA1, No PFS, 3600s

This needs to be configured in OPNsense under VPN > IPsec after the migration.

---

## Firewall Rules Summary (Configured on OPNsense)

| Rule | Interface | Source | Destination | Port | Action |
|------|-----------|--------|-------------|------|--------|
| WAN HTTPS | WAN | Any | WAN address | 443 | Allow |
| WAN SSH | WAN | Any | WAN address | 22 | Allow |
| WAN ICMP | WAN | Any | WAN address | ICMP | Allow |
| WAN WireGuard | WAN | Any | WAN address | 51820/UDP | Allow |
| WireGuard to all | Floating | 10.10.10.0/24 | Any | Any | Allow |
| All to WireGuard | Floating | Any | 10.10.10.0/24 | Any | Allow |
| VLAN1 allow all | opt2 | VLAN1 net | Any | Any | Allow |
| VLAN2 allow all | opt3 | VLAN2 net | Any | Any | Allow |
| VLAN100 allow all | opt4 | VLAN100 net | Any | Any | Allow |

---

## DHCP Static Reservations (Configured on OPNsense)

| MAC Address | IP Address | Hostname | VLAN | Notes |
|-------------|-----------|----------|------|-------|
| 18:66:da:9f:0d:0d | 172.16.0.5 | node01-idrac | 1 | |
| 44:a8:42:15:2a:70 | 172.16.0.6 | node02-idrac | 1 | |
| 44:a8:42:03:c1:48 | 172.16.0.7 | node03-idrac | 1 | iservices01's iDRAC |
| 78:45:c4:f7:74:6e | 172.16.0.8 | node03-test | 1 | Not seen on Meraki since 2026-03-21 |
| ec:f4:bb:d3:04:a8 | 172.16.0.22 | iservices01 | 1 | node03 mgmt |
| 24:6e:96:5f:37:5c | 172.16.0.29 | controller01 | 1 | node01 mgmt |
| ec:f4:bb:d5:2a:d4 | 172.16.0.41 | compute001 | 1 | node02 mgmt, hosts 13+ VMs |
| 2c:ea:7f:fc:e2:74 | 172.16.0.51 | idrac-52XLK93 | 1 | **NEW** — needs OPNsense reservation |
| 2c:ea:7f:fc:d3:98 | 172.16.0.53 | idrac-532GK93 | 1 | **NEW** — needs OPNsense reservation |
| 2c:ea:7f:fc:db:2a | 192.168.38.160 | idrac-5DQQK93 | 2 | iDRAC for **ludus physical server** (will be reinstalled) |
| 00:10:18:f6:45:9b | 192.168.38.187 | acirt01 | 2 | |
| 34:80:0d:bf:36:00 | 192.168.38.195 | ludus01 | 2 | **NEW** — Cavium server, OS to be reinstalled |
| 00:11:32:e9:1f:c7 | 192.168.38.232 | ITSL-NAS | 2 | |

---

## Port Forwarding Rules (To Configure on OPNsense)

| Description | WAN | External Port | Internal IP | Internal Port | Protocol |
|-------------|-----|---------------|-------------|---------------|----------|
| Cyberrange uplink | WAN2 | 8843 | 192.168.38.8 | 443 | TCP |
