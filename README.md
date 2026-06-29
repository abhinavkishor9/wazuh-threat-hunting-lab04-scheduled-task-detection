# wazuh-threat-hunting-lab05-scheduled-task-detection
## Objective

Detect Windows Scheduled Task activity using Sysmon and investigate the generated telemetry in Wazuh Threat Hunting.

This lab demonstrates how scheduled task creation appears in Sysmon Event ID 1 logs and how Wazuh ingests and displays those events for investigation.

---

## Lab Environment

### Manager
- Wazuh Manager

### Endpoint
- Windows 11
- Wazuh Agent
- Sysmon

---

## MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1053.005 | Scheduled Task / Job: Scheduled Task |

---

## Tools Used

- Wazuh
- Sysmon
- PowerShell
- Windows Task Scheduler

---

## Verification Steps

### Verify Wazuh Agent

```powershell
Get-Service WazuhSvc
```

Status should be:

```
Running
```

---

### Verify Sysmon

```powershell
Get-Service Sysmon64
```

Status should be:

```
Running
```

---

### Verify Sysmon Logging

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Create Scheduled Task

```cmd
schtasks /create /tn "WazuhLabTask" /tr "notepad.exe" /sc once /st 23:59
```

Expected output:

```
SUCCESS: The scheduled task "WazuhLabTask" has successfully been created.
```

---

## Verify Scheduled Task

```cmd
schtasks /query /tn "WazuhLabTask"
```

---

## Verify Sysmon Event ID 1

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 20 | Where-Object {$_.Message -match "schtasks.exe"}
```

---

## Review Event Details

Important fields observed:

- Process Image
- Command Line
- User
- Parent Process
- Process GUID
- Hashes
- Integrity Level

---

## Verify in Wazuh Threat Hunting

Search for:

```
schtasks.exe
```

Review:

- Event Details
- Process Image
- Command Line
- Event Timestamp
- Agent Name
- Rule Information

---

## Detection Summary

Detection Source:
- Sysmon Event ID 1

Observed Activity:
- Scheduled Task Creation
- Scheduled Task Query

MITRE Technique:
- T1053.005

Result:
- Successful detection inside Wazuh Threat Hunting

---

## Learning Outcomes

- Detect Scheduled Task activity
- Understand Sysmon Event ID 1
- Hunt for Windows persistence techniques
- Investigate process metadata in Wazuh
- Map findings to MITRE ATT&CK
