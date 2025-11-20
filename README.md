# Threat Hunt Report: Unauthorized Port Scanning Incident

<img width="1028" height="684" alt="port_scanning_IIId_bordered" src="https://github.com/user-attachments/assets/3c1a2369-fa68-49aa-b761-b00dc242677b" />

##  Scenario

The server team noticed a significant network performance degradation on some of the older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally. All traffic originating from within the local network is allowed by default by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.
- [Scenario Creation](https://github.com/iojini/sudden-network-slowdowns/blob/main/sudden-network-slowdowns-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table

Searched for excessive failed connections requests from devices on the network and discovered that the user "irene-test-vm-mde" failed several connection requests against itself (it's own IP address) and another host on the same network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
<img width="2845" height="627" alt="S2QR1v4" src="https://github.com/user-attachments/assets/0a5059bd-9582-436e-8bf9-881b1aed00cb" />

---

### 2. Searched the `DeviceNetworkEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the logs returned, at `2025-10-04T19:16:45.455884Z`, an employee on the "irene-test-vm-m" device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "irene-test-vm-m"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="3117" height="398" alt="TOR2" src="https://github.com/user-attachments/assets/94bcf1aa-dc1f-4ccc-89b7-57035c52d433" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-10-04T19:20:39.986612Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "irene-test-vm-m"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
<img width="3154" height="1534" alt="TOR3" src="https://github.com/user-attachments/assets/805a97c7-b644-4400-9c5e-40916cf12531" />

---

## Summary

The user "labuser" on the "irene-test-vm-m" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `irene-test-vm-m` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
