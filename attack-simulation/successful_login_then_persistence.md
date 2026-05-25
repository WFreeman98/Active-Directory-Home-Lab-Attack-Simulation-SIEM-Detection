# Detection 15: Successful Login Then Persistence

## Objective

Detect a successful remote logon followed by persistence activity.

This detection identifies a multi event sequence where a successful logon is followed by local account creation and local administrator group membership modification. In this lab, a successful RDP logon was followed by creation of a local account named `svc_backup` and addition of that account to the local Administrators group.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access / Defense Evasion | T1078 - Valid Accounts | Administrator successfully logged in using RDP. |
| Persistence | T1136.001 - Create Account: Local Account | A local account named `svc_backup` was created. |
| Persistence / Privilege Escalation | T1098 - Account Manipulation | `svc_backup` was added to the local Administrators group. |

## Log Source

- Windows Security Logs
- Splunk Universal Forwarder
- Windows Event ID 4624: An account was successfully logged on
- Windows Event ID 4720: A user account was created
- Windows Event ID 4732: A member was added to a security enabled local group
- Host: Target-PC

## Detection Logic

This detection looks for a sequence of authentication and persistence related events:

1. **Event ID 4624**  
   Confirms a successful logon.

2. **Event ID 4720**  
   Confirms a new user account was created.

3. **Event ID 4732**  
   Confirms the new account was added to a local security group such as Administrators.

This sequence can indicate post authentication persistence, where an attacker uses valid access and then creates or elevates an account to maintain future access.

## SPL Queries

Successful RDP logon:

```spl
index=endpoint host="Target-PC" EventCode=4624 "192.168.10.250"
| table _time EventCode host ComputerName Account_Name Logon_Type Source_Network_Address _raw
| sort -_time
```

Persistence account creation:

```spl
index=endpoint host="Target-PC" EventCode=4720 "svc_backup"
| table _time EventCode host ComputerName _raw
| sort -_time
```

Administrator group membership change:

```spl
index=endpoint host="Target-PC" EventCode=4732 "svc_backup"
| table _time EventCode host ComputerName _raw
| sort -_time
```

## Safe Attack Simulation

A successful RDP login was performed from Kali to Target-PC using a valid administrative account.

The source IP for the successful logon was:

```text
192.168.10.250
```

A local account was then created on Target-PC:

```cmd
net user svc_backup * /add
```

The account was added to the local Administrators group:

```cmd
net localgroup Administrators svc_backup /add
```

The account was verified using:

```cmd
net user svc_backup
```

The password was entered through the hidden prompt and was not recorded in screenshots.

## Detection Result

Splunk identified the multi event sequence:

```text
4624 - Administrator successfully logged in using RDP from 192.168.10.250
4720 - Local account svc_backup was created
4732 - svc_backup was added to the local Administrators group
```

Observed evidence:

```text
Source IP: 192.168.10.250
Target Host: Target-PC
Logon Type: 10
Logged-in Account: Administrator
Persistence Account: svc_backup
Group Added To: Administrators
```

## Analyst Thought Process

### Initial Alert Meaning

A successful logon followed by account creation and administrator group membership modification can indicate post-compromise persistence. While each event may be legitimate on its own, the sequence is more suspicious when it occurs shortly after a remote logon or from an unusual source.

### Key Questions

- Which account successfully logged in?
- Was the logon remote or local?
- What source IP initiated the logon?
- Was the source system expected?
- Which account created the new user?
- Why was the new account created?
- Was the new account added to a privileged group?
- Did this occur during an approved administrative change?
- Was there related activity such as scheduled task creation, service creation, PowerShell execution, or Defender tampering?

### Evidence Reviewed

- Windows Security Event ID 4624
- Logon Type 10 remote interactive logon
- Source network address
- Windows Security Event ID 4720 account creation
- Windows Security Event ID 4732 local group membership change
- Account names
- Hostname
- Raw Windows Security event data

## Analyst Investigation Summary

A successful RDP logon to Target-PC was observed from Kali at `192.168.10.250`. The logon used the `Administrator` account and generated Windows Security Event ID `4624` with Logon Type `10`.

Shortly after the successful logon, a local account named `svc_backup` was created, generating Event ID `4720`. The account was then added to the local Administrators group, generating Event ID `4732`.

This sequence simulates a common post-authentication persistence pattern where valid access is used to create or elevate an account for continued access.

## Severity

High

A successful login followed by account creation and privileged group modification should be treated as high severity when the activity is unexpected, occurs from an unusual source, involves privileged accounts, or is not tied to an approved change.

## False Positive Considerations

- Authorized administrator account provisioning
- Help desk account recovery activity
- IT maintenance activity
- Lab-generated simulation activity
- Approved service account creation
- Known onboarding or system administration work

This detection becomes more suspicious when paired with brute force attempts, suspicious PowerShell, scheduled task creation, service creation, Defender tampering, event log clearing, or LSASS access.

## Recommended Response

- Identify the source IP and originating host.
- Confirm whether the successful logon was authorized.
- Identify the account used for the logon.
- Review the newly created account.
- Check whether the account was added to privileged groups.
- Validate whether the account creation was approved.
- Review surrounding activity before and after the logon.
- Search for the same account across other systems.
- Disable or remove the account if unauthorized.
- Reset credentials if account compromise is suspected.
- Escalate if the activity appears malicious or part of a broader attack chain.
- Document the full timeline.

## Cleanup

After validation, the test account was removed using:

```cmd
net localgroup Administrators svc_backup /delete
net user svc_backup /delete
```

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Windows Security Event ID 4624 showing successful RDP logon from Kali | <img width="624" height="379" alt="4624 Logon Type 10 from Kali IP" src="https://github.com/user-attachments/assets/79640665-3aad-4bb7-a97a-9415e74acf3d" /> |
| Windows Security Event ID 4720 showing `svc_backup` account creation | <img width="624" height="394" alt="svc_backup account exists and is in Administrators" src="https://github.com/user-attachments/assets/df1ae9e1-6b85-43e6-9003-e6c37daa7500" /> |
| Windows Security Event ID 4732 showing `svc_backup` added to Administrators | <img width="624" height="325" alt="4732 showing svc_backup added to Administrators" src="https://github.com/user-attachments/assets/dc1885b7-28f7-4bcd-800c-5f15faa08da1" /> |

## Analyst Conclusion

In my conclusion, a successful login followed by account creation and privileged group modification is a high value sequence to investigate because it can indicate an attacker using valid access to establish persistence. This lab showed how Windows Security Event IDs 4624, 4720, and 4732 can be used together to validate the timeline from remote logon to local account persistence. In a real investigation, I would review the source IP, logged-in account, new account name, group membership change, timing, authorization status, and surrounding endpoint activity to determine whether the sequence was legitimate or suspicious.
