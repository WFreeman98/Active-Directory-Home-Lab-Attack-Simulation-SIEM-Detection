# Detection Validation Matrix

| # | Detection | Attack Simulation | Expected Log Source | Expected Event ID / Telemetry | Status | Screenshot |
|---|-----------|------------------|---------------------|-------------------------------|--------|------------|
| 1 | RDP Brute Force | Hydra failed RDP logons | Windows Security | 4625 / Logon Type 3 | Validated | [Evidence](../attack-simulation/hydra_rdp_bruteforce.md) |
| 2 | Successful Login After Failures | Hydra failures followed by valid RDP login | Windows Security | 4625 + 4624 | Validated | [Evidence](../attack-simulation/successful_login_after_failures.md) |
| 3 | Password Spraying | Hydra against multiple users | Windows Security | 4625 | Validated | [Evidence](../attack-simulation/password_spraying.md) |
| 4 | New Account Created | net user / Atomic Red Team | Windows Security | 4720 | Planned | Pending |
| 5 | Privileged Group Change | Add user to admin group | Windows Security | 4728 / 4732 | Planned | Pending |
| 6 | Encoded PowerShell | Safe encoded PowerShell command | Sysmon | Event ID 1 | Planned | Pending |
| 7 | PowerShell Download Cradle | Invoke-WebRequest from Kali web server | Sysmon | Event ID 1 / 3 | Planned | Pending |
| 8 | LSASS Access / Credential Dumping | Atomic Red Team T1003.001 controlled test | Sysmon | Event ID 10 ProcessAccess to lsass.exe | Planned | Pending |
| 9 | Event Log Clearing | wevtutil test | Windows/Sysmon | 1102 / Event ID 1 | Planned | Pending |
| 10 | Defender Tampering | Defender tampering command simulation | Windows System / Sysmon | Event ID 1 | Planned | Pending |
| 11 | Scheduled Task Created | schtasks test | Windows/Sysmon | 4698 / Event ID 1 | Planned | Pending |
| 12 | New Service Installed | sc.exe create test service | Windows System / Sysmon | 7045 / Event ID 1 | Planned | Pending |
| 13 | LOLBin Spawning Shell | rundll32/mshta spawning cmd/powershell | Sysmon | Event ID 1 | Planned | Pending |
| 14 | Internal Network Scan | Nmap scan from Kali | Sysmon/Firewall | Event ID 3 / firewall logs | Planned | Pending |
| 15 | Successful Login Then Persistence | 4624 followed by 4720/4732 | Windows Security | 4624 + 4720/4732 | Planned | Pending |
