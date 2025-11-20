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

## Summary

The user "labuser" on the "irene-test-vm-m" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `irene-test-vm-m` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
