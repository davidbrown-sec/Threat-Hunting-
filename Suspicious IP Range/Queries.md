# Advanced Hunting Queries – RCE Investigation

This document collects the hunting queries used during investigation of suspicious outbound connections to the **208.89.73.0/24** subnet.

---

## 🔹 Initial Connection Hunt
Identify all network events targeting the suspicious IP range.
Microsoft Defender For Endpoint

```kusto
DeviceNetworkEvents
| where RemoteIP startswith "208.89.73."
| where RemotePort == 80
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, ActionType



DeviceNetworkEvents
| where RemoteIP startswith "208.89.73."
| where RemotePort == 80
| project Timestamp,
          DeviceName,
          LocalIP, LocalPort,
          RemoteIP, RemotePort,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessFolderPath,
          InitiatingProcessSHA256,
          InitiatingProcessParentFileName
