# Active Directory SIEM Detection Lab

## Overview

This project simulates a Windows Active Directory enterprise environment used to generate, detect, and investigate realistic attacker activity with Splunk, Sysmon, and Windows Security telemetry.

The goal of this lab is to document a SOC-style detection engineering workflow: simulate attack behavior, validate telemetry, build SPL detections, map activity to MITRE ATT&CK, review false positives, and document response actions.

All attack simulations were performed in an isolated lab environment using controlled, non-malicious testing.

---

## Network Architecture

<img width="649" height="553" alt="Lab architecture" src="https://github.com/user-attachments/assets/6a08cc82-be36-40ef-8bd2-05fc6318c967" />

*Active Directory detection lab with centralized Splunk log ingestion from domain systems.*

---

## Lab Environment

| Component | Purpose |
|---|---|
| Windows Server 2022 - DC01 | Active Directory Domain Controller |
| Windows 10 - WS01 / Target-PC | Domain-joined workstation |
| Kali Linux | Attack simulation system |
| Ubuntu Server | Splunk SIEM platform |
| Sysmon | Endpoint telemetry collection |
| Splunk Universal Forwarder | Windows log forwarding |
| Hydra | Authentication attack simulation |
| Atomic Red Team | MITRE ATT&CK simulation |

---

## Detection Engineering Focus Areas

- Windows Security Event analysis
- Sysmon telemetry analysis
- Splunk SPL detection development
- Active Directory attack simulation
- Authentication attack detection
- Privileged group monitoring
- PowerShell abuse detection
- Credential access detection
- Defense evasion detection
- MITRE ATT&CK mapping
- SOC triage and investigation workflow
- Detection validation methodology

---

## Detection Methodology

Each detection followed the same validation process:

1. Simulate attacker behavior in the isolated lab.
2. Confirm expected Windows or Sysmon telemetry.
3. Build and test SPL detection logic in Splunk.
4. Review raw event data and key investigation fields.
5. Map activity to MITRE ATT&CK.
6. Document severity, false positives, and response considerations.
7. Capture screenshots as validation evidence.
8. Update the detection validation matrix.

---

## Detection Coverage

**Current progress:** 9 of 15 detections validated. Remaining detections are planned for future expansion.

### Detection Rule Index

| # | Detection | MITRE ATT&CK | Status | Evidence |
|---|-----------|--------------|--------|----------|
| 1 | RDP Brute Force | T1110, T1021.001 | Validated | [Evidence](attack-simulation/hydra_rdp_bruteforce.md) |
| 2 | Successful Login After Failures | T1110, T1078, T1021.001 | Validated | [Evidence](attack-simulation/successful_login_after_failures.md) |
| 3 | Password Spraying | T1110.003, T1021.001 | Validated | [Evidence](attack-simulation/password_spraying.md) |
| 4 | New Account Created | T1136.002 | Validated | [Evidence](attack-simulation/new_account_created.md) |
| 5 | Privileged Group Change | T1098 | Validated | [Evidence](attack-simulation/privileged_group_change.md) |
| 6 | Encoded PowerShell | T1059.001, T1027 | Validated | [Evidence](attack-simulation/encoded_powershell.md) |
| 7 | PowerShell Download Cradle | T1105, T1059.001 | Validated | [Evidence](attack-simulation/powershell_download_cradle.md) |
| 8 | LSASS Access / Credential Dumping | T1003.001 | Validated | [Evidence](attack-simulation/lsass_access.md) |
| 9 | Event Log Clearing | T1070.001 | Validated | [Evidence](attack-simulation/event_log_clearing.md) |
| 10 | Defender Tampering | T1562.001 | Validated | [Evidence](attack-simulation/defender_tampering.md) |
| 11 | Scheduled Task Created | T1053.005 | Validated | [Evidence](attack-simulation/scheduled_task_created.md) |
| 12 | New Service Installed | T1543.003 | Validated | [Evidence](attack-simulation/new_service_installed.md) |
| 13 | Certutil File Download | T1105, T1218 | Validated | [Evidence](attack-simulation/certutil_file_download.md) |
| 14 | Internal Network Scan | T1046 | Validated | [Evidence](attack-simulation/internal_network_scan.md) |
| 15 | Successful Login Then Persistence | T1078, T1136, T1098 | Planned | Pending |

The full validation tracker is available here:

[Detection Validation Matrix](validation/detection_validation_matrix.md)

---

## Key Investigation Concepts Demonstrated

- Correlating failed and successful authentication activity
- Investigating RDP/NLA authentication behavior
- Detecting password spraying patterns
- Reviewing Active Directory account creation
- Monitoring privileged group changes
- Detecting encoded PowerShell execution
- Investigating PowerShell network connections
- Detecting suspicious LSASS process access
- Investigating Windows Security log clearing
- Mapping detection logic to MITRE ATT&CK techniques

---

## Lab Build Evidence

<details>
<summary><strong>Stage 1: Virtual Machine Deployment</strong></summary>

Built a multi-machine lab environment using VirtualBox.

<img width="662" height="591" alt="Virtual Machines" src="https://github.com/user-attachments/assets/116d14a8-486e-4d61-86c0-4e2d72598e4d" />

<img width="546" height="629" alt="Virtual Machine Kali" src="https://github.com/user-attachments/assets/242e9add-7d70-4aa0-9775-120f55323654" />

<img width="544" height="592" alt="VM Windows 2022" src="https://github.com/user-attachments/assets/c887fe1f-8e01-4765-9017-8e6f3078ea5e" />

<img width="662" height="589" alt="VM SIEM" src="https://github.com/user-attachments/assets/fa09d407-d5c0-40db-84a6-a45b45b9f310" />

</details>

---

<details>
<summary><strong>Stage 2: Network Configuration</strong></summary>

Configured static IP addressing and validated internal connectivity between lab systems.

<img width="662" height="178" alt="Network Connectivity" src="https://github.com/user-attachments/assets/2aa40b2f-0112-4d3f-a552-1867306c0d5d" />

<img width="647" height="172" alt="SIEM Static IP" src="https://github.com/user-attachments/assets/441bf0cf-84d6-4041-a72d-c77681333a74" />

</details>

---

<details>
<summary><strong>Stage 3: Active Directory Setup</strong></summary>

Configured the `corp.local` Active Directory domain, organizational structure, and test user accounts.

<img width="662" height="507" alt="Active Directory Setup" src="https://github.com/user-attachments/assets/e21dc146-2ae1-48aa-8969-4939a98463ee" />

</details>

---

<details>
<summary><strong>Stage 4: Domain Integration</strong></summary>

Joined the Windows workstation to the Active Directory domain and validated domain registration.

<img width="411" height="402" alt="Domain J" src="https://github.com/user-attachments/assets/fce8fdf9-569b-46da-8ff6-c4b988380bab" />

<img width="662" height="464" alt="Domain Join" src="https://github.com/user-attachments/assets/a8ae7cf7-9210-45bf-af64-6e0f0a3026b2" />

</details>

---

<details>
<summary><strong>Stage 5: Sysmon and Splunk Log Ingestion</strong></summary>

Deployed Sysmon and forwarded Windows Security and Sysmon telemetry into Splunk.

<img width="581" height="190" alt="Sysmon Running" src="https://github.com/user-attachments/assets/e9986a1d-80a1-4589-9391-03fe39439f85" />

<img width="597" height="550" alt="Sysmon Event Viewer" src="https://github.com/user-attachments/assets/615edd37-0850-4edd-b590-84dc1c5a978a" />

<img width="662" height="469" alt="Splunk Log Ingestion" src="https://github.com/user-attachments/assets/2500f254-2cf7-4e99-9160-f3c007708576" />

</details>

---

## Example Attack Simulations

### RDP Brute Force Simulation

Hydra was used from Kali to generate repeated failed RDP authentication attempts against the domain workstation.

<img width="649" height="512" alt="Hydra Attack" src="https://github.com/user-attachments/assets/78124f35-ffdc-4a65-98d3-7c881a27278d" />

---

### Atomic Red Team Persistence Simulation

Atomic Red Team was used to simulate account creation activity mapped to MITRE ATT&CK.

<img width="662" height="523" alt="Atomic Execution" src="https://github.com/user-attachments/assets/a1e503e6-335c-4fa1-a4c6-c9cadd363f5f" />

<img width="662" height="467" alt="Account Creation Detection" src="https://github.com/user-attachments/assets/a3ae763d-2fbe-4496-9156-53ffd1e334a6" />

---

## Example Detection Evidence

Splunk was used to validate attack activity through Windows Security and Sysmon telemetry.

<img width="1000" height="635" alt="Splunk Detection" src="https://github.com/user-attachments/assets/eab62698-2eba-46ba-bc8e-fdad82a70455" />

*Example Splunk results showing failed authentication activity associated with brute-force behavior.*

---

## Investigation Workflow

After generating attack telemetry, each alert was investigated using raw event review, field analysis, and SPL correlation.

### Authentication Investigation

The lab investigated failed RDP authentication activity, successful logons after repeated failures, and password spraying patterns.

Key fields reviewed included:

- Source IP address
- Targeted account
- Destination host
- Event ID
- Logon type
- Failure count
- Successful authentication activity after failed attempts

### Persistence Investigation

The lab reviewed Active Directory account creation and privileged group changes.

Key investigation questions included:

- Was the account creation authorized?
- Who created or modified the account?
- Was the account added to a privileged group?
- Did the account log in after creation?
- Was there follow-on activity?

### Defense Evasion and Credential Access Investigation

The lab also validated detections for encoded PowerShell execution, LSASS process access, and Windows Security log clearing.

These detections focused on identifying suspicious process behavior, credential access indicators, and attempts to remove evidence from the host.

---

## SOC Response Considerations

In a production SOC environment, these alerts would require validation of the source system, targeted account, affected host, and follow-on activity.

Potential response actions include:

- Confirming whether activity was authorized
- Reviewing successful logons after failed authentication attempts
- Resetting affected account passwords when compromise is suspected
- Removing unauthorized privileged group membership
- Disabling unauthorized accounts
- Reviewing PowerShell, process creation, and network telemetry
- Preserving centralized logs for investigation
- Isolating affected hosts if credential access or compromise is confirmed
- Documenting the full incident timeline

---

## Limitations

This project was built in a controlled home lab environment rather than a production enterprise network. Some detections use lab-specific hostnames, usernames, and IP addresses for validation purposes.

Future improvements include:

- Generalized SPL detection logic
- Multi-host correlation rules
- Sigma rule conversion
- SOAR integration
- Automated alerting
- Expanded attack-chain correlation
- Additional detections for scheduled tasks, service creation, Defender tampering, LOLBins, and internal scanning

---

## Repository Structure

```text
Active-Directory-SIEM-Detection-Lab/
│
├── README.md
├── attack-simulation/
│   ├── hydra_rdp_bruteforce.md
│   ├── successful_login_after_failures.md
│   ├── password_spraying.md
│   ├── new_account_created.md
│   ├── privileged_group_change.md
│   ├── encoded_powershell.md
│   ├── powershell_download_cradle.md
│   ├── lsass_access.md
│   └── event_log_clearing.md
│
├── validation/
│   └── detection_validation_matrix.md
│
└── images/
    └── project screenshots
