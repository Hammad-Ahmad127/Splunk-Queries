# Splunk-Queries
A collection of custom Splunk Processing Language (SPL) queries, detection rules, and SIEM monitoring logs designed for threat hunting  and security operations

# Account creation and Deletion Alert:
Detects when someone creates a new user account, deletes an existing account, or modifies privileged group memberships.   Event IDs: 4720, 4726, 4728, 4732, 4756MITRE ATT&CK: Persistence / Privilege Escalation (T1136, T1098)

```spl```

index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4720, 4726, 4728, 4732, 4756)
| eval Action=case(
    EventCode==4720, "User Account Created",
    EventCode==4726, "User Account Deleted",
    EventCode==4728, "Added to Global Security Group",
    EventCode==4732, "Added to Local Security Group",
    EventCode==4756, "Added to Universal Security Group"
)
| table _time, host, Action, SubjectUserName, TargetUserName, GroupName
| sort -_time

# Brute Force Alert:
Detects multiple failed password login attempts from a single source IP or against a specific target account within a short time window.   Event ID: 4625MITRE ATT&CK: Credential Access (T1110)Splunk SPL

```spl```

index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count as Failed_Attempts, values(TargetUserName) as Targeted_Users by IpAddress, host
| where Failed_Attempts >= 5
| eval Severity=if(Failed_Attempts >= 15, "CRITICAL", "HIGH")
| table host, IpAddress, Targeted_Users, Failed_Attempts, Severity
| sort -Failed_Attempts

# Clearing Windows Event Logs Alert:
Detects defense evasion attempts where an attacker clears Windows Security or System event logs to hide their tracks.   Event IDs: 1102, 104MITRE ATT&CK: Defense Evasion (T1070.001)
```spl```
index=wineventlog (EventCode=1102 OR EventCode=104)
| eval Log_Cleared=if(EventCode==1102, "Security Audit Log Cleared", "System/Application Event Log Cleared")
| eval Severity="CRITICAL"
| table _time, host, Log_Cleared, SubjectUserName, SubjectDomainName, Severity
| sort -_time

# 4. Pass the Hash / Kerberos Ticket Attack Alert:
Detects Pass-the-Hash (PtH), Pass-the-Ticket (PtT), or anomalous Kerberos authentication attempts using RC4 encryption downgrade.   Event IDs: 4768, 4769, 4624MITRE ATT&CK: Lateral Movement (T1550.002, T1550.003)

```spl```

index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4768 OR EventCode=4769 OR (EventCode=4624 LogonType=9))
| where TicketEncryptionType="0x17" OR LogonProcessName="seclogo"
| eval Attack_Vector=case(
    LogonType==9, "Pass-the-Hash (NewCredentials Logon)",
    TicketEncryptionType=="0x17", "Kerberoasting / RC4 Ticket Anomaly",
    true(), "Kerberos Ticket Anomaly"
)
| table _time, host, Attack_Vector, TargetUserName, IpAddress, ServiceName
| sort -_time

# Potential Data Exfiltration (High Outbound Traffic) Alert:
Monitors firewall and network telemetry for unusually large outbound data transfers to external IP addresses.   Data Source: Firewall / Network Traffic (network, firewall)MITRE ATT&CK: Exfiltration (T1048)

```spl```

index=network OR sourcetype=*firewall* action=allowed
| where NOT cidrmatch("10.0.0.0/8", dest_ip) AND NOT cidrmatch("192.168.0.0/16", dest_ip) AND NOT cidrmatch("172.16.0.0/12", dest_ip)
| stats sum(bytes_out) as Total_Bytes_Out, count as Connections by src_ip, dest_ip, dest_port
| eval Outbound_MB=round(Total_Bytes_Out / 1048576, 2)
| where Outbound_MB > 100
| table src_ip, dest_ip, dest_port, Connections, Outbound_MB
| sort -Outbound_MB

# 6. Suspicious Command Line Execution Detection Alert:
Flags obfuscated PowerShell commands, encoded payloads, and living-off-the-land binaries (LOLBins) via Process Creation logs.   Event IDs: 4688 (Windows Security) / 1 (Sysmon)MITRE ATT&CK: Execution (T1059.001)

```spl```

index=wineventlog (EventCode=4688 OR EventCode=1)
| where match(CommandLine, "(?i)(-enc|-encodedcommand|whoami|net user|mimikatz|certutil.*-urlcache|powershell.*-w hidden|bypass)")
| eval Risk_Level="HIGH"
| table _time, host, User, ParentImage, NewProcessName, CommandLine, Risk_Level
| sort -_time
