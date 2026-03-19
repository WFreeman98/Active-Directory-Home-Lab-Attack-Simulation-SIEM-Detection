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

![Lab Architecture](architecture.png)


*Lab architecture showing domain controller, workstation, attacker machine, and Splunk SIEM with centralized log forwarding*

---

## Key Project Stages

### Stage 1: Virtual Machine Deployment

Built a multi-machine lab environment using VirtualBox.

![Virtual Machines](vms.png)

*Virtual machines deployed in VirtualBox representing domain controller, workstation, attacker system, and SIEM server*

---

### Stage 2: Network Configuration

Configured static IP addressing and validated connectivity.

![Network Connectivity](ping.png)

*Successful network connectivity between lab machines verified using ping across internal network*

![SIEM Static IP](ipconfig.png)

*SIEM server configured with static IP address to ensure reliable log ingestion*

---

### Stage 3: Active Directory Setup

Configured Active Directory domain and enterprise structure.

![Active Directory Setup](ad-users.png)

*Active Directory domain (corp.local) with organizational units and user accounts configured on domain controller*

---

### Stage 4: Domain Integration

Joined workstation to the domain.

![Domain Join](domain.png)

*Workstation successfully joined to domain with authentication verified using domain credentials*

![AD Computer Object](ad-computer.png)

*Domain workstation visible in Active Directory confirming successful registration*

---

### Stage 5: Sysmon and Log Forwarding

Deployed Sysmon and centralized logs in Splunk.

![Sysmon Running](sysmon.png)

*Sysmon service running on endpoint generating detailed telemetry including process and logon activity*

![Event Viewer Sysmon](eventviewer.png)

*Windows Event Viewer displaying Sysmon logs for endpoint activity monitoring*

![Splunk Log Ingestion](splunk-logs.png)

*Splunk receiving endpoint telemetry confirming successful log ingestion from domain systems*

---

### Stage 6: Attack Simulation

#### RDP Brute Force (Hydra)

![Hydra Attack](hydra.png)

*Hydra brute force attack generating multiple failed RDP login attempts against target user account*

#### Atomic Red Team (Persistence Simulation)

![Atomic Execution](atomic.png)

*Atomic Red Team execution simulating account creation (MITRE ATT&CK T1136.001)*

![Account Creation Detection](event4720.png)

*Splunk event showing account creation (EventCode 4720) indicating persistence behavior*

---

### Stage 7: Detection

Detection performed using Splunk queries.

![Splunk Detection](splunk4625.png)

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

## Detection Queries (Examples)

```spl
index=endpoint
