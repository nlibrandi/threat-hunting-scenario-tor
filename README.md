# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src=(https://github.com/nlibrandi/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nico-threat-hun"
| where InitiatingProcessAccountName == "nicolib1"
| where FileName contains "tor"
| where Timestamp >= datetime(Jun 6, 2025 9:42:39 AM)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
![Screenshot 1](https://github.com/user-attachments/assets/fdb03ae2-d172-42e7-8400-b9950e9d2263)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nico-threat-hun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Screenshot 2](https://github.com/user-attachments/assets/a43e84ed-a96d-4c5b-9309-c0ebfe8e026f)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nico-threat-hun"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
![Screenshot 3](https://github.com/user-attachments/assets/50c56811-32c0-4164-8527-abf20166378b)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "nico-threat-hun"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040","9050","9051","9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```![Screenshot 4](https://github.com/user-attachments/assets/9bfcff42-6f43-4826-bf6b-e5fe6abde4a7)


---

Chronological Events
Phase 1: Download
🕓 Jun 6, 2025 — 9:44:59 AM


Action: Tor installer downloaded.


File: tor-browser-windows-x86_64-portable-14.5.3.exe


Location: C:\Users\nicolib1\Downloads


User: nicolib1


SHA256: 3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46...



💾 Phase 2: Installation and Extraction
🕓 Jun 6, 2025 — 9:45:55 AM to 9:49:13 AM


Multiple FileCreated Events in Tor Browser directories indicate the unpacking or installation of the browser, including:


storage-sync-v2.sqlite


webappsstore.sqlite


User: nicolib1


Location: C:\Users\nicolib1\Desktop\Tor Browser\...



🚀 Phase 3: Process Execution
🕓 Jun 6, 2025 — 9:49:21 AM to 9:50:02 AM


tor.exe and multiple firefox.exe processes created, indicating that the Tor Browser was launched.


Location: C:\Users\nicolib1\Desktop\Tor Browser\Browser\...


Command: "tor.exe" -f ...



📄 Phase 4: User File Activity
🕓 Jun 6, 2025 — 9:56:56 AM to 9:57:49 AM


Files Created and Renamed:


TOR shopping list.txt and .lnk file created.


Renamed later to: tor-shopping-list.txt.txt


Possible user notes or activity related to Tor usage.



🌐 Phase 5: Network Activity
🕓 Jun 6, 2025 — 9:45:59 AM


Network Connection Success


Executable: tor.exe


Destination IP: 75.145.166.70


Port: 9001 (commonly used for Tor entry nodes)

---

## Summary

The user nicolib1 downloaded the official Tor Browser installer at 9:44 AM.


The browser was installed/unpacked in a Desktop directory.


By 9:49 AM, tor.exe and multiple firefox.exe processes were running, signaling the launch of Tor Browser.


A successful connection was established by tor.exe to a remote IP on port 9001 — consistent with Tor network activity.


Shortly after, the user created and renamed a file labeled TOR shopping list, suggesting post-usage documentation or intent.

---

## Response Taken

TOR usage was confirmed on endpoint  “nico-threat-hun” by the user “nlibrandi1”. The device was isolated and the user's direct manager was notified.

---
