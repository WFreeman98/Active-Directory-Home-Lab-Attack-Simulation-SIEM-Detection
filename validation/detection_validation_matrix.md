# Detection Validation Matrix

| # | Detection | Attack Simulation | Expected Log Source | Expected Event ID / Telemetry | Status | Screenshot |
|---|-----------|------------------|---------------------|-------------------------------|--------|------------|
| 1 | RDP Brute Force | Hydra failed RDP logons | Windows Security | 4625 / Logon Type 3 | Validated | [Evidence](../attack-simulation/hydra_rdp_bruteforce.md) |
| 2 | Successful Login After Failures | Hydra failures followed by valid RDP login | Windows Security | 4625 + 4624 | Validated | [Evidence](../attack-simulation/successful_login_after_failures.md) |
| 3 | Password Spraying | Hydra against multiple users | Windows Security | 4625 | Validated | [Evidence](../attack-simulation/password_spraying.md) |
| 4 | New Account Created | Active Directory Users and Computers | Windows Security | 4720 | Validated | [Evidence](../attack-simulation/new_account_created.md) |
| 5 | Privileged Group Change | Add user to Domain Admins | Windows Security | 4728 | Validated | [Evidence](../attack-simulation/privileged_group_change.md) |
| 6 | Encoded PowerShell | Safe encoded PowerShell command | Sysmon | Event ID 1 | Validated | [Evidence](../attack-simulation/encoded_powershell.md) |
| 7 | PowerShell Download Cradle | Invoke-WebRequest from Kali web server | Sysmon | Event ID 1 / 3 | Validated | [Evidence](../attack-simulation/powershell_download_cradle.md) |
| 8 | LSASS Access / Credential Dumping | Safe LSASS process access simulation | Sysmon | Event ID 10 ProcessAccess to lsass.exe | Validated | [Evidence](../attack-simulation/lsass_access.md) |
| 9 | Event Log Clearing | wevtutil test | Windows Security | 1102 | Validated | [Evidence](../attack-simulation/event_log_clearing.md) |
| 10 | Defender Tampering | Defender tampering command simulation | Sysmon | Event ID 1 | Validated | [Evidence](../attack-simulation/defender_tampering.md) |
| 11 | Scheduled Task Created | schtasks test | Windows/Sysmon | 4698 / Event ID 1 | Validated | [Evidence](../attack-simulation/scheduled_task_created.md) |
| 12 | New Service Installed | sc.exe create test service | Windows System / Sysmon | 7045 / Event ID 1 | Validated | [Evidence](../attack-simulation/new_service_installed.md) |
| 13 | Certutil File Download | certutil download from Kali web server | Sysmon / Windows Defender | Event ID 1 / Event ID 3 / Defender Alert | Validated | [Evidence](../attack-simulation/certutil_file_download.md) |
| 14 | Internal Network Scan | Nmap scan from Kali | Windows Security / Firewall | Event ID 5156 | Validated | [Evidence](../attack-simulation/internal_network_scan.md) |
| 15 | Successful Login Then Persistence | 4624 followed by 4720/4732 | Windows Security | 4624 + 4720/4732 | Validated | [Evidence](../attack-simulation/successful_login_then_persistence.md) |
