# Active Directory SIEM Detection Lab

## Objective

This project simulates a real-world enterprise environment using Active Directory, endpoint telemetry, and a SIEM platform to detect and investigate cyber attacks. The objective was to generate realistic attack activity and analyze logs in Splunk to understand how SOC analysts identify, investigate, and respond to threats.

---

## Lab Environment

- **Domain Controller:** Windows Server 2022 (DC01)
- **Workstation:** Windows 10 (WS01)
- **Attacker Machine:** Kali Linux
- **SIEM Platform:** Ubuntu Server (Splunk)
- **Tools:** Sysmon, Splunk Universal Forwarder, Hydra, Atomic Red Team

---

## Skills Demonstrated

- SIEM log ingestion and analysis using Splunk  
- Endpoint telemetry collection with Sysmon  
- Active Directory configuration and domain management  
- Attack simulation (brute force and persistence techniques)  
- Threat detection using Windows Security Events  
- Log correlation and investigation  
- MITRE ATT&CK mapping  

---

## Network Architecture

<img width="649" height="553" alt="Lab architecture" src="https://github.com/user-attachments/assets/6a08cc82-be36-40ef-8bd2-05fc6318c967" />



*Lab architecture showing domain controller, workstation, attacker machine, and Splunk SIEM with centralized log forwarding*

---

## Key Project Stages

### Stage 1: Virtual Machine Deployment

Built a multi-machine lab environment using VirtualBox.

<img width="662" height="591" alt="Virtual Machines" src="https://github.com/user-attachments/assets/116d14a8-486e-4d61-86c0-4e2d72598e4d" />
<img width="546" height="629" alt="Virtual Machine Kali" src="https://github.com/user-attachments/assets/242e9add-7d70-4aa0-9775-120f55323654" />
<img width="544" height="592" alt="VM Windows 2022" src="https://github.com/user-attachments/assets/c887fe1f-8e01-4765-9017-8e6f3078ea5e" />
<img width="662" height="589" alt="VM SIEM" src="https://github.com/user-attachments/assets/fa09d407-d5c0-40db-84a6-a45b45b9f310" />


*Virtual machines deployed in VirtualBox representing domain controller, workstation, attacker system, and SIEM server*

---

### Stage 2: Network Configuration

Configured static IP addressing and validated connectivity.

<img width="662" height="178" alt="Network Connectivity" src="https://github.com/user-attachments/assets/2aa40b2f-0112-4d3f-a552-1867306c0d5d" />

*Successful network connectivity between lab machines verified using ping across internal network*
<img width="647" height="172" alt="SIEM Static IP" src="https://github.com/user-attachments/assets/441bf0cf-84d6-4041-a72d-c77681333a74" />

*SIEM server configured with static IP address to ensure reliable log ingestion*

---

### Stage 3: Active Directory Setup

Configured Active Directory domain and enterprise structure.

<img width="662" height="507" alt="Active Directory Setup" src="https://github.com/user-attachments/assets/e21dc146-2ae1-48aa-8969-4939a98463ee" />


*Active Directory domain (corp.local) with organizational units and user accounts configured on domain controller*

---

### Stage 4: Domain Integration

Joined workstation to the domain.

<img width="411" height="402" alt="Domain J" src="https://github.com/user-attachments/assets/fce8fdf9-569b-46da-8ff6-c4b988380bab" />



*Workstation successfully joined to domain with authentication verified using domain credentials*

<img width="662" height="464" alt="Domain Join" src="https://github.com/user-attachments/assets/a8ae7cf7-9210-45bf-af64-6e0f0a3026b2" />

*Domain workstation visible in Active Directory confirming successful registration*

---

### Stage 5: Sysmon and Log Forwarding

Deployed Sysmon and centralized logs in Splunk.

<img width="581" height="190" alt="Sysmon Running" src="https://github.com/user-attachments/assets/e9986a1d-80a1-4589-9391-03fe39439f85" />


*Sysmon service running on endpoint generating detailed telemetry including process and logon activity*

<img width="597" height="550" alt="Sysmon Event Viewer" src="https://github.com/user-attachments/assets/615edd37-0850-4edd-b590-84dc1c5a978a" />


*Windows Event Viewer displaying Sysmon logs for endpoint activity monitoring*

<img width="662" height="469" alt="Splunk Log Ingestion" src="https://github.com/user-attachments/assets/2500f254-2cf7-4e99-9160-f3c007708576" />


*Splunk receiving endpoint telemetry confirming successful log ingestion from domain systems*

---

### Stage 6: Attack Simulation

#### RDP Brute Force (Hydra)

<img width="649" height="512" alt="Hydra Attack" src="https://github.com/user-attachments/assets/78124f35-ffdc-4a65-98d3-7c881a27278d" />


*Hydra brute force attack generating multiple failed RDP login attempts against target user account*

#### Atomic Red Team (Persistence Simulation)

<img width="662" height="523" alt="Atomic Execution" src="https://github.com/user-attachments/assets/a1e503e6-335c-4fa1-a4c6-c9cadd363f5f" />


*Atomic Red Team execution simulating account creation (MITRE ATT&CK T1136.001)*

<img width="662" height="467" alt="Account Creation Detection" src="https://github.com/user-attachments/assets/a3ae763d-2fbe-4496-9156-53ffd1e334a6" />


*Splunk event showing account creation (EventCode 4720) indicating persistence behavior*

---

### Stage 7: Detection

Detection performed using Splunk queries.

<img width="1000" height="635" alt="Splunk Detection" src="https://github.com/user-attachments/assets/eab62698-2eba-46ba-bc8e-fdad82a70455" />


*Splunk search results showing failed authentication attempts (EventCode 4625) indicating brute force activity*

---

### Stage 8: Investigation

Following detection of suspicious activity, investigation was performed.

#### Brute Force Activity Analysis

- Target: WS01  
- User: bwaltz  
- Attack: RDP brute force  

Logs showed repeated failed login attempts, confirming password guessing behavior originating from the attacker system.

#### Persistence Activity Analysis

- Technique: T1136.001  

Logs confirmed unauthorized account creation, indicating persistence behavior.

#### Key Findings

- Repeated failed login attempts = brute force  
- Single account targeted  
- Unauthorized account creation detected  
- Activity aligns with known attack techniques  

#### MITRE ATT&CK Mapping

| Technique | Description |
|----------|------------|
| T1110 | Brute Force |
| T1136.001 | Create Local Account |
| T1021 | Remote Services (RDP) |

---

## SOC Response Considerations  

In a real SOC environment, repeated failed authentication attempts would be flagged as potential brute force activity. Analysts would investigate the source system, review successful login attempts, and determine whether the account was compromised.

If confirmed, the account would be locked or reset, and additional monitoring would be applied to detect further suspicious behavior. Unauthorized account creation would be treated as persistence and escalated for further investigation.

---

## Detection Engineering Rules

This section contains 15 Splunk detection rules built from the Active Directory home lab. Each detection includes the attack behavior, MITRE ATT&CK mapping, SPL query, severity, false positive considerations, analyst thought process, and response steps.

The purpose of this section is to document how alerts are triaged and investigated in a SOC-style workflow. Each detection follows this process:

1. Simulate attacker behavior in the isolated lab.
2. Confirm the expected Windows or Sysmon telemetry is generated.
3. Build a Splunk SPL detection rule.
4. Validate the detection using real lab logs.
5. Document the analyst thought process.
6. Capture screenshots as evidence.
7. Update the validation matrix.

### Detection Rule Index

| # | Detection | MITRE ATT&CK | Status | Evidence |
|---|-----------|--------------|--------|----------|
| 1 | RDP Brute Force | T1110, T1021.001 | Validated | [Evidence](attack-simulation/hydra_rdp_bruteforce.md) |
| 2 | Successful Login After Failures | T1110, T1078, T1021.001 | Validated | [Evidence](attack-simulation/successful_login_after_failures.md) |
| 3 | Password Spraying | T1110.003, T1021.001 | Validated | [Evidence](attack-simulation/password_spraying.md) |
| 4 | New Account Created | T1136.002 | Validated | [Evidence](attack-simulation/new_account_created.md) |
| 5 | Privileged Group Change | T1098 | Validated | [Evidence](attack-simulation/privileged_group_change.md) |
| 6 | Encoded PowerShell | T1059.001 | Planned | Pending |
| 7 | PowerShell Download Cradle | T1105, T1059.001 | Planned | Pending |
| 8 | LSASS Access / Credential Dumping | T1003.001 | Planned | Pending |
| 9 | Event Log Clearing | T1070.001 | Planned | Pending |
| 10 | Defender Tampering | T1562.001 | Planned | Pending |
| 11 | Scheduled Task Created | T1053.005 | Planned | Pending |
| 12 | New Service Installed | T1543.003 | Planned | Pending |
| 13 | LOLBin Spawning Shell | T1218 | Planned | Pending |
| 14 | Internal Network Scan | T1046 | Planned | Pending |
| 15 | Successful Login Then Persistence | T1078, T1136, T1098 | Planned | Pending |

### Validation Matrix

The full detection validation tracker is located here:

[Detection Validation Matrix](validation/detection_validation_matrix.md)
