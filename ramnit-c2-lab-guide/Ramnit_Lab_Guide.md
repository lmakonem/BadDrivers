# Ramnit C2 Investigation – Security Onion + Wireshark

## Lab overview

- Analyze a pre‑captured Ramnit malware infection.  
- Identify the infected host and C2 servers.  
- Use Suricata alerts and Zeek logs in Security Onion.  
- Confirm C2 behavior in Wireshark.  
- Understand limits of the dataset (no ransom note in this PCAP).

---

## 1. Connect to Security Onion

1. On the Windows lab machine:

   - Click **Start**.  
   - Type `cmd`.  
   - Right‑click **Command Prompt** → **Run as administrator**.

2. In the Command Prompt window, type:

   ```bash
   ssh user@192.168.1.200
   ```

   Press **Enter**.

3. When asked for the password, type:

   ```text
   password
   ```

   Press **Enter**.

You are now logged in to the Security Onion server.

---

## 2. Download and import the PCAP

1. In the SSH window, run:

   ```bash
   mkdir -p ~/pcaps
   cd ~/pcaps
   ```

2. Download the PCAP ZIP:

   ```bash
   wget https://www.malware-traffic-analysis.net/2017/11/21/2017-11-21-traffic-analysis-exercise-1-of-6.pcap.zip
   ```

3. Unzip the PCAP:

   ```bash
   unzip -P infected_20171121 2017-11-21-traffic-analysis-exercise-1-of-6.pcap.zip
   ```

4. Confirm the file is present:

   ```bash
   ls
   ```

   You must see:

   ```text
   2017-11-21-traffic-analysis-exercise-1-of-6.pcap
   ```

5. Import the PCAP:

   ```bash
   sudo so-import-pcap 2017-11-21-traffic-analysis-exercise-1-of-6.pcap
   ```

6. When prompted for the password, type:

   ```text
   password
   ```

   Press **Enter**.

7. When the command finishes, find the URL that begins with:

   ```text
   https://192.168.1.200/
   ```

   Select the entire URL, right‑click → **Copy**, and paste it into Notepad on the Windows desktop.

---

## 3. Open SOC and Hunt

1. On Windows, open **Edge** or **Chrome**.

2. Paste the URL into the address bar and press **Enter**.

3. Log in:

   ```text
   Username: user
   Password: password
   ```

4. Click **Hunt** in the top menu.

5. Set the time range:

   - Click the time control (top‑right).  
   - Choose **Absolute**.  
   - Set:

     ```text
     Start: 2017-11-20 18:15:00
     End:   2017-11-20 18:25:00
     ```

   - Click **Apply**.

---

## 4. Identify the infected host and C2 servers

1. In the search bar, type:

   ```kql
   event.dataset:"suricata.alert"
   ```

   Press **Enter**.

2. Enable columns:

   - `@timestamp`  
   - `source.ip`  
   - `source.port`  
   - `destination.ip`  
   - `destination.port`  
   - `rule.name`  
   - `event.severity_label`

3. Scroll and find which internal `source.ip` appears most often in high‑severity alerts.  
   You will see many alerts from `192.168.1.121`.

4. Record:

   ```text
   Infected internal host: 192.168.1.121
   ```

5. Filter on this host:

   ```kql
   event.dataset:"suricata.alert" AND source.ip:"192.168.1.121"
   ```

   Press **Enter**.

6. From these alerts, record:

   - C2 IPs: values of `destination.ip` (217.20.116.142, 194.87.110.230).  
   - C2 port: value of `destination.port` (443).  
   - Signature: `ET MALWARE Win32/Ramnit Checkin`.  
   - Severity: `high`.

---

## 5. Inspect a Ramnit alert

1. Use this query:

   ```kql
   event.dataset:"suricata.alert"
   AND source.ip:"192.168.1.121"
   AND rule.name:"ET MALWARE Win32/Ramnit Checkin"
   ```

   Press **Enter**.

2. Click any row where:

   - `destination.ip` = `194.87.110.230`  
   - `destination.port` = `443`

3. In the details panel, find:

   - `rule.category` = `Malware Command and Control Activity Detected`  
   - `rule.metadata.malware_family` = `Ramnit`  
   - In `rule.rule`, note:

     ```text
     dsize:6;
     content:"|00 ff|";
     content:"|00 00|";
     ```

   - `payload_printable` = `..K...`

4. Answer in your notes:

   - What does this rule say about the size and pattern of the payload?  
   - Why is a 6‑byte payload to port 443 suspicious?

---

## 6. Analyze C2 behavior with Zeek conn

1. Search:

   ```kql
   event.dataset:"zeek.conn" AND source.ip:"192.168.1.121"
   ```

   Press **Enter**.

2. Enable columns:

   - `@timestamp`  
   - `destination.ip`  
   - `destination.port`  
   - `network.transport`  
   - `source.bytes`  
   - `destination.bytes`

3. Restrict to C2:

   ```kql
   event.dataset:"zeek.conn"
   AND source.ip:"192.168.1.121"
   AND destination.port:443
   AND (destination.ip:"217.20.116.142" OR destination.ip:"194.87.110.230")
   ```

   Press **Enter**.

4. Sort by `@timestamp`.

5. Count connections to each C2 IP and note how small the `source.bytes` / `destination.bytes` values are.

6. In your notes, describe the pattern (for example, frequent short connections that look like beacons).

---

## 7. DNS investigation

1. Search:

   ```kql
   event.dataset:"zeek.dns" AND source.ip:"192.168.1.121"
   ```

   Press **Enter**.

2. Enable columns:

   - `@timestamp`  
   - `dns.question.name`  
   - `dns.question.type`  
   - `dns.response_code`

3. List all `dns.question.name` values in your notes.

4. Mark each as "expected" or "suspicious" based on your judgement.

5. If an answers column (such as `dns.answers.data`) is available, check whether any domains resolve to the C2 IPs. Record any domain → C2 mappings you find.

---

## 8. HTTP investigation

1. Search:

   ```kql
   event.dataset:"zeek.http"
   AND (source.ip:"192.168.1.121" OR destination.ip:"192.168.1.121")
   ```

   Press **Enter**.

2. Enable columns:

   - `@timestamp`  
   - `http.host`  
   - `url.full` or `http.uri`  
   - `http.request.method`  
   - `http.response.status_code`

3. If HTTP rows exist, copy each full URL into your notes and label it "normal" or "suspicious".

4. If there are no HTTP rows, write: "No HTTP traffic involving 192.168.1.121 in this capture."

---

## 9. Download PCAP for a Ramnit C2 flow

1. In Hunt, return to Ramnit alerts:

   ```kql
   event.dataset:"suricata.alert"
   AND source.ip:"192.168.1.121"
   AND rule.name:"ET MALWARE Win32/Ramnit Checkin"
   ```

   Press **Enter**.

2. Choose one alert where:

   - `destination.ip` is a C2 IP.  
   - `destination.port` is 443.

3. Right‑click that alert row and click **Download PCAP**.

4. Save the file to the Windows Desktop with the name:

   ```text
   ramnit-session.pcap
   ```

---

## 10. Analyze the C2 flow in Wireshark

1. Open **Wireshark** on Windows.

2. Click **File → Open…** and open `ramnit-session.pcap`.

3. In the filter field, type:

   ```wireshark
   ip.src == 192.168.1.121 && tcp.port == 443
   ```

   Press **Enter**.

4. Observe:

   - SYN / SYN‑ACK / ACK.  
   - One or more short data packets.

5. Right‑click a data packet → **Follow → TCP Stream**.

6. Set **Show and save data as** to **ASCII**.  
   Read the content.

7. Note: the stream contains only very small C2 payloads. There is no ransom note or large text file in this PCAP.

Write in your notes:

> This capture shows Ramnit C2 beacons only. There is no ransom‑note file in the network data.

---

## 11. Internal connections (lateral movement check)

1. In Hunt, search:

   ```kql
   event.dataset:"zeek.conn"
   AND source.ip:"192.168.1.121"
   AND NOT destination.ip:"217.20.116.142"
   AND NOT destination.ip:"194.87.110.230"
   ```

   Press **Enter**.

2. Look for:

   - Internal destination IPs (for example 192.168.1.x).  
   - Ports like 445 (SMB) or 3389 (RDP).

3. Record any such connections and decide whether they look like lateral movement attempts.

---

## 12. Large outbound transfers (exfiltration check)

1. In Hunt, search:

   ```kql
   event.dataset:"zeek.conn" AND source.ip:"192.168.1.121"
   ```

   Press **Enter**.

2. Click the `source.bytes` column twice so the largest values appear at the top.

3. For each external destination with unusually large `source.bytes`, record:

   - `@timestamp`  
   - `destination.ip`  
   - `destination.port`  
   - `source.bytes`

4. Decide whether any of these look like possible data exfiltration. If all values are small, state that no large outbound transfers are visible.

---

## 13. Final incident summary (student task)

Write a short incident summary that answers:

- Which internal host is infected?  
- Which external IPs and port are used for C2?  
- Which Suricata rule and malware family identify the infection?  
- How does the Zeek connection data show beaconing behavior?  
- What DNS activity did you see for the infected host?  
- Is there evidence of HTTP traffic, lateral movement, or data exfiltration?  
- What response actions should be taken next?

---

## Key learning outcomes

Upon completion of this lab, students will understand:

1. **Network Security Monitoring (NSM) fundamentals**: How Suricata creates alerts and Zeek logs connections, DNS, and HTTP.

2. **Malware signature detection**: How IDS rules identify C2 communication based on unique payload patterns.

3. **C2 beacon analysis**: How to recognize repeated small connections as indicators of active C2 versus normal traffic.

4. **DNS pivoting**: How to use domain queries to correlate with external servers.

5. **PCAP analysis**: How to use Wireshark to validate findings and extract stream data.

6. **Incident response**: How to collect evidence systematically and document findings for remediation.

---

## Recommended tools and resources

- [Security Onion Solutions](https://securityonionsolutions.com) – NSM platform  
- [Zeek Network Security Monitor](https://zeek.org) – Network analysis framework  
- [Suricata](https://suricata.io) – Open IDS/IPS engine  
- [Wireshark](https://www.wireshark.org) – Packet analysis  
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) – Sample PCAPs  

---

**Document version**: 1.0  
**Last updated**: December 3, 2025  
**Audience**: Cybersecurity students and incident responders