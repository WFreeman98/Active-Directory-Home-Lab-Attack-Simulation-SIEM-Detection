# Active-Directory-Home-Lab-Attack-Simulation-SIEM-Detection

## Objective

This project simulates a real-world enterprise environment using Active Directory, endpoint telemetry, and a SIEM platform to detect and investigate cyber attacks. The goal was to generate realistic attack activity and analyze logs in Splunk to understand how SOC analysts identify and respond to threats.

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

*Lab Architechture Diagram*  
This diagram shows the virtualized lab environment consisting of a domain controller, workstation, attacker machine, and Splunk SIEM server connected within a private network. Logs are forwarded from endpoints to Splunk for centralized analysis.

---

## Key Project Stages

### Stage 1: Virtual Machine Deployment
Created a multi-machine lab environment using VirtualBox, including Windows Server, Windows 10, Kali Linux, and Ubuntu Server.

---

### Stage 2: Network Configuration
Configured static IP addressing and validated connectivity between all machines using ping tests to ensure proper communication across the environment.

---

### Stage 3: Active Directory Setup
Installed and configured Active Directory Domain Services on the Windows Server and created the **corp.local** domain. Organizational units and users were created to simulate an enterprise environment.

---

### Stage 4: Domain Integration
Joined the Windows 10 workstation (WS01) to the domain and verified successful domain authentication.

---

### Stage 5: Sysmon and Log Forwarding
Installed Sysmon on both the domain controller and workstation to generate detailed endpoint telemetry. Configured the Splunk Universal Forwarder to send logs to the SIEM server.

*Ref 2: Sysmon and Log Ingestion*  
Logs from both systems were successfully ingested into Splunk, confirming centralized log collection.

---

### Stage 6: Attack Simulation

#### RDP Brute Force (Hydra)
Simulated a brute force attack from Kali Linux targeting the WS01 workstation using Hydra. Multiple failed login attempts were generated.

*Ref 3: Hydra Attack Execution*  

#### Atomic Red Team (Persistence Simulation)
Executed MITRE ATT&CK technique **T1136.001 (Create Local Account)** to simulate persistence.

*Ref 4: Atomic Red Team Execution*

---

### Stage 7: Detection

Detection was performed in Splunk by analyzing Windows Security logs and Sysmon telemetry.

- Failed logon attempts identified using authentication logs  
- Unauthorized account creation detected through security events  
- Detection refined using targeted searches and event correlation  

*Ref 5: Splunk Detection Results*

---

### Stage 8: Investigation

The attack activity was investigated by analyzing logs in Splunk:

- Multiple failed authentication attempts identified from the attacker machine  
- Target user account: **bwaltz**  
- Activity confirmed as brute force behavior  
- Persistence activity identified through new user account creation  

The observed activity was mapped to MITRE ATT&CK techniques:

| Technique | Description |
|----------|------------|
| T1110 | Brute Force |
| T1136.001 | Create Local Account |
| T1021 | Remote Services (RDP) |

---

## Detection Queries (Examples)

```spl
index=endpoint
