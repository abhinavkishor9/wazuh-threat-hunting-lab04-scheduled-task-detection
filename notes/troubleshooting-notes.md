# Troubleshooting Notes

## Issue 1

### Problem

Scheduled Task event did not appear in Wazuh.

### Resolution

Verified:

```powershell
Get-Service WazuhSvc
```

Confirmed:

```
Running
```

---

## Issue 2

### Problem

No Sysmon events were visible.

### Resolution

Verified:

```powershell
Get-Service Sysmon64
```

Confirmed:

```
Running
```

Checked recent Sysmon events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Issue 3

### Problem

Unable to locate Event ID 1.

### Resolution

Filtered specifically for Process Creation:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]"
```

---

## Issue 4

### Problem

Unable to locate Scheduled Task process.

### Resolution

Filtered Sysmon Event ID 1 events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 20 | Where-Object {$_.Message -match "schtasks.exe"}
```

---

## Issue 5

### Problem

Needed to verify scheduled task creation.

### Resolution

Executed:

```cmd
schtasks /query /tn "WazuhLabTask"
```

Confirmed:

```
Ready
```

---

## Issue 6

### Problem

Needed to verify task creation succeeded.

### Resolution

Executed:

```cmd
schtasks /create /tn "WazuhLabTask" /tr "notepad.exe" /sc once /st 23:59
```

Received:

```
SUCCESS
```

---

## Issue 7

### Problem

Wanted to confirm Wazuh received endpoint telemetry.

### Resolution

Opened Wazuh Threat Hunting and searched for:

```
schtasks.exe
```

Verified:

- Agent information
- Process metadata
- Event timestamp
- Command line
- Event details

---

## Lessons Learned

- Sysmon Event ID 1 captures process creation activity.
- Scheduled Task operations generate observable telemetry.
- Wazuh successfully ingests Sysmon process creation events.
- Filtering Event ID 1 simplifies threat hunting for process execution.
- Scheduled Tasks are a common persistence mechanism mapped to MITRE ATT&CK T1053.005.
