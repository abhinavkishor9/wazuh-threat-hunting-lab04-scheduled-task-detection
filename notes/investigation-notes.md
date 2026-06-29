# Investigation Notes

## Scenario

A Scheduled Task was created on the Windows endpoint to simulate a common persistence technique used by adversaries.

The objective was to verify that Sysmon captured the activity and Wazuh successfully ingested the event.

---

## Activity Performed

Created a scheduled task:

```cmd
schtasks /create /tn "WazuhLabTask" /tr "notepad.exe" /sc once /st 23:59
```

Verified task:

```cmd
schtasks /query /tn "WazuhLabTask"
```

Verified Sysmon logging:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 20 | Where-Object {$_.Message -match "schtasks.exe"}
```

---

## Evidence Collected

### Process Name

```
schtasks.exe
```

---

### Command Line

```
schtasks /query /tn "WazuhLabTask"
```

---

### User

```
DESKTOP-9MMM37V\Dell
```

---

### Parent Process

```
explorer.exe
```

---

### Event Source

```
Sysmon Event ID 1
```

---

### Wazuh Detection

The event appeared successfully inside Wazuh Threat Hunting.

Observed metadata included:

- Agent ID
- Agent Name
- Process Image
- Command Line
- Hashes
- File Version
- Company
- Timestamp

---

## MITRE ATT&CK Mapping

Technique

```
T1053.005
```

Technique Name

```
Scheduled Task / Job
```

Tactic

```
Persistence
```

---

## Analyst Assessment

The activity was intentionally generated as part of a controlled lab.

No malicious payload was executed.

The detection confirmed:

- Sysmon captured process creation
- Wazuh received endpoint telemetry
- Threat Hunting displayed the event successfully

---

## Conclusion

The lab successfully demonstrated detection of Windows Scheduled Task activity using Sysmon Event ID 1 and Wazuh Threat Hunting, validating the end-to-end telemetry pipeline from endpoint to SIEM.
