# Detection 03: Password Spraying

## Objective

Detect password spraying activity against multiple Windows domain user accounts.

This detection identifies repeated Windows Security Event ID 4625 failed logons from the same source IP against multiple user accounts. In this lab, Hydra was used from Kali to attempt a single password across multiple domain users on Target-PC.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110.003 - Password Spraying | A single password was attempted against multiple domain user accounts from the same source IP. |
| Lateral Movement | T1021.001 - Remote Services: Remote Desktop Protocol | The authentication attempts targeted RDP on the domain workstation. |

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 4625

## Detection Logic

This detection looks for failed authentication attempts from the same source IP against multiple user accounts.

Password spraying is different from brute forcing. In a brute-force attack, many passwords are tried against one account. In a password spraying attack, one password is tried against many accounts.

In this lab, the failed RDP/NLA authentication attempts appeared as Logon Type 3.

## SPL Query

```spl
index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=lower(coalesce(TargetUserName, Account_Name))
| where source_ip="192.168.10.250"
| stats count as failure_count dc(user) as unique_users values(user) as targeted_users values(Logon_Type) as logon_types by source_ip host ComputerName
| where unique_users >= 3 AND failure_count >= 3
| sort -unique_users
```

## Attack Simulation

Hydra was used from the Kali Linux attacker machine to attempt one password across multiple domain user accounts.

Example user list:

```text
PWaltz@corp.local
AJones@corp.local
TLee@corp.local
BWaltz@corp.local
JGarcia@corp.local
MJones@corp.local
```

Example command:

```bash
hydra -L spray_users.txt -p 'Kali2026' rdp://192.168.10.100 -V -t 1
```

The sprayed password was intentionally incorrect, which generated failed authentication attempts.

## Detection Result

The detection identified multiple failed logon attempts from source IP `192.168.10.250` against several domain user accounts.

The activity targeted `Target-PC` and generated Windows Security Event ID 4625 failures. The failed logons appeared as Logon Type 3, consistent with RDP/NLA authentication behavior.

## Analyst Thought Process

### Initial Alert Meaning

A single source IP generating failed logons against multiple users may indicate password spraying.

### Key Questions

- What source IP generated the failed logons?
- How many unique users were targeted?
- Was the same password attempted across multiple accounts?
- Were the attempts against a single host or multiple hosts?
- Did any account successfully authenticate after the spray?

### Evidence Reviewed

- Event ID 4625
- Multiple targeted domain users
- Source IP: 192.168.10.250
- Target host: Target-PC
- Logon Type: 3
- Failure reason: unknown username or bad password
- Unique user count
- Failure count

## Analyst Investigation Summary

I began by validating the raw Windows Security telemetry in Splunk. Target-PC generated multiple Event ID 4625 failed logons from the Kali attacker IP address, `192.168.10.250`.

Unlike the RDP brute-force detection, this activity involved multiple user accounts instead of repeated attempts against only one user. This pattern is more consistent with password spraying, where an attacker tests a common password across several accounts to avoid lockouts.

I then grouped the failed logons by source IP and counted the number of unique targeted users. The detection showed multiple user accounts receiving failed logons from the same source IP, supporting the password spraying behavior.

The next investigation step would be to check whether any of the targeted users had a successful Event ID 4624 logon after the spray. If a successful login occurred, the investigation would escalate to possible account compromise.

## Severity

Medium

Increase to High if any targeted account has a successful Event ID 4624 logon after the spray.

## False Positive Considerations

- Help desk or administrator testing
- Misconfigured authentication scripts
- Users mistyping shared or temporary passwords
- Lab-generated authentication testing
- Password policy or onboarding testing

This detection becomes more suspicious when the source IP is unusual, the number of targeted users is high, the activity occurs in a short time window, or a successful login follows the failed attempts.

## Recommended Response

- Identify the source IP and determine whether it is expected.
- Review the list of targeted accounts.
- Search for successful Event ID 4624 logons after the spray.
- Check whether the same source IP targeted additional hosts.
- Review for account lockouts or additional authentication failures.
- Reset passwords for affected accounts if compromise is suspected.
- Enforce MFA and account lockout protections where possible.
- Document the full authentication timeline.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Hydra password spray from Kali | <img width="624" height="282" alt="03_hydra_password_spray" src="https://github.com/user-attachments/assets/28bbfe5e-93c8-4509-833b-9c27e2045602" /> |
| Raw Event ID 4625 failed logons against multiple users | <img width="624" height="308" alt="03_raw_4625_multiple_users" src="https://github.com/user-attachments/assets/07cdf712-0470-4a37-b2ce-0b11b01511b3" /> |
| Splunk detection showing multiple targeted users from one source IP | <img width="624" height="255" alt="03_password_spraying_detection" src="https://github.com/user-attachments/assets/45af8170-bd86-41c6-be2e-1f5ba94a260a" /> |

## Analyst Conclusion

This detection successfully identified password spraying behavior against multiple domain user accounts. Hydra was used from Kali to attempt one password across several users, and Target-PC generated Windows Security Event ID 4625 failed logons from source IP `192.168.10.250`.

The activity should be treated as suspected password spraying because the same source IP targeted multiple user accounts in a short period. The most important next step is to determine whether any targeted account had a successful Event ID 4624 logon after the spray.
