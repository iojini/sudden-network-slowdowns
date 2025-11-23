# Threat Event (Sudden Network Slowdowns)
**Lateral Reconnaissance via Port Scanning**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Provision a Windows VM and confirm the VM is reachable externally (e.g., ping)
2. Onboard the VM to Microsoft Defender for Endpoint (MDE)
3. Run the following PowerShell script on the onboarded VM to simulate lateral reconnaissance and port scanning:<br>
    [Port Scan Simulation Script](https://github.com/iojini/sudden-network-slowdowns/blob/main/scripts/portscan.ps1)

---

## Tables Used for IoC Identification:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect failed connection requests and evidence of port scanning.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect the time and source of the port script launch.|

---

