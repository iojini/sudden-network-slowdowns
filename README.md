# Threat Hunt Report: Unauthorized Port Scanning Incident

<img width="1028" height="684" alt="port_scanning_IIId_bordered" src="https://github.com/user-attachments/assets/3c1a2369-fa68-49aa-b761-b00dc242677b" />

##  Scenario

The server team noticed a significant network performance degradation on some of the older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally. All traffic originating from within the local network is allowed by default by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.
- [Scenario Creation](https://github.com/iojini/sudden-network-slowdowns/blob/main/sudden-network-slowdowns-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- Log Repository: Azure Log Analytics
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table for Failed Connection Requests

Searched for excessive failed connections requests from devices on the network and discovered that the user "irene-test-vm-mde" failed several connection requests against itself (it's own IP address) and another host on the same network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
<img width="2009" height="422" alt="S2R2QR1" src="https://github.com/user-attachments/assets/80ac7488-76b3-4852-978d-52f1742ecc8a" />

---

### 2. Searched the `DeviceNetworkEvents` Table for Total Failed Connections

After observing failed connection requests from a suspected host (10.1.0.242), it was clear a port scan was taken place due to the sequential order of the ports. There were several port scans being conducted.

**Query used to locate event:**

```kql
let IPInQuestion = "10.1.0.242";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by TimeGenerated asc
```
<img width="2049" height="786" alt="S2R2QR2" src="https://github.com/user-attachments/assets/971a3df8-0994-4eb8-8cb5-16eb6a841b57" />

---

### 3. Searched the `DeviceProcessEvents` Table for Port Scan Source

Searched for suspicious events occurring around the time the port scan started and noticed that a PowerShell script named portscan.ps1 launched at 2025-10-01T20:03:16.6270327Z.

**Query used to locate events:**

```kql
let VMName = "irene-test-vm-m";
let specificTime = datetime(2025-10-01T20:03:36.2217304Z);
DeviceProcessEvents
| where TimeGenerated  between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by TimeGenerated desc
| project TimeGenerated, FileName, InitiatingProcessCommandLine

```
<img width="2267" height="917" alt="S2R2QR3" src="https://github.com/user-attachments/assets/8cf064b1-40ba-494a-bafc-ef13a627e2b7" />

---

### 4. Located Port Scan Script on Device

Logged into the suspect computer and observed the PowerShell script that was used to conduct the port scan. An excerpt of script can be found below.

<img width="2052" height="962" alt="PS_script_S2v4_bordered" src="https://github.com/user-attachments/assets/c4c66356-154b-4e0f-9e7d-ef824d270675" />

---

## Summary

The user "labuser" on the "irene-test-vm-m" device (10.1.0.242) initiated and executed a PowerShell script named portscan.ps1 located in C:\programdata. The script was launched with execution policy bypass at 2025-10-01T20:03:16.627Z, bypassing standard security controls. The device then generated a high volume of failed connection requests against multiple hosts on the local network, scanning ports sequentially (21, 22, 23, 25, 53, 69, 80, 110, 123, etc). This sequence of activities indicates that the user actively deployed and executed a port scanning tool to perform reconnaissance against other hosts on the 10.0.0.0/16 network, likely to identify open services and potential vulnerabilities.

---

## Response Taken

Unauthorized port scanning activity was confirmed on the endpoint "irene-test-vm-m" originating from a PowerShell script executed by the user "labuser". This behavior was not expected and was not configured by administrators. The device was isolated, and a malware scan was performed with no findings. As a precaution, the device remains isolated and a ticket has been submitted to have it reimaged.

---

## Relevant MITRE ATT&CK TTPs

| Tactic | TTP Name | TTP ID | Description | Detection Relevance |
|--------|----------|:--------:|-------------|---------------------|
| Discovery | Network Service Discovery | T1046 | A PowerShell script (portscan.ps1) was executed to scan multiple hosts on the 10.0.0.0/16 network, probing common ports sequentially (21, 22, 23, 25, 53, 69, 80, 110, 123, etc.). | Identifies reconnaissance activity through failed connection attempts logged in DeviceNetworkEvents table. |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | The port scan was conducted via a PowerShell script launched with execution policy bypass (-ExecutionPolicy Bypass). | Identifies suspicious PowerShell execution through DeviceProcessEvents table, including command line arguments. |
| Defense Evasion | Masquerading | T1036 | The script was placed in C:\ProgramData\, a common location used to blend in with legitimate software, and logged to "entropygorilla.log" to obscure its purpose. | Identifies potentially malicious files stored in commonly abused directories. |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified internal reconnaissance activity (port scanning from an endpoint) and confirmed unauthorized use of PowerShell scripts executed by the user "labuser".

---
