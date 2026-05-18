# Detection 05: Privileged Group Change

## Objective

Detect when a user is added to a privileged Active Directory group.

This detection identifies Windows Security Event ID `4728`, which is generated when a member is added to a security-enabled global group. In this lab, the domain user `LTest` / `Lab Test` was added to the `Domain Admins` group in Active Directory Users and Computers.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | T1098 - Account Manipulation | A domain user was added to the privileged `Domain Admins` group. |
| Privilege Escalation | T1098 - Account Manipulation | Adding a user to `Domain Admins` can grant high-level privileges across the domain. |

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 4728
- Domain Controller: DC01

## Detection Logic

This detection looks for Event ID `4728` on the domain controller when a user is added to a privileged Active Directory group.

Adding a user to `Domain Admins` is a high-impact change because members of this group have administrative control over the domain. In a real environment, this activity should be reviewed to confirm it was authorized and expected.

## SPL Query

```spl
index=endpoint host="DC01" EventCode=4728
| search "Domain Admins" "Lab Test"
| eval actor=SubjectUserName
| table _time EventCode host ComputerName actor Account_Name _raw
| sort -_time
```

## Attack Simulation

The privileged group change was performed in Active Directory Users and Computers on DC01.

Action performed:

```text
Added Lab Test / LTest to Domain Admins
```

Location:

```text
Active Directory Users and Computers
corp.local > Users > Domain Admins > Members
```

This action generated Windows Security Event ID `4728` on DC01.

## Detection Result

Splunk detected Event ID `4728` after the user was added to `Domain Admins`.

The event showed:

```text
Event ID: 4728
Host: DC01
Actor: Administrator
User added: Lab Test / LTest
Group changed: Domain Admins
```

## Analyst Thought Process

### Initial Alert Meaning

A user was added to a privileged Active Directory group. This may be legitimate administrative activity, but it can also indicate privilege escalation or persistence if the change was unauthorized.

### Key Questions

- What user was added to the group?
- What group was modified?
- Who performed the change?
- Was the change approved?
- Was the new privileged account used to log in afterward?
- Did the same actor make other account or group changes?

### Evidence Reviewed

- Event ID 4728
- Added user: Lab Test / LTest
- Modified group: Domain Admins
- Actor account: Administrator
- Host: DC01
- Domain: CORP / corp.local

## Analyst Investigation Summary

I began by adding the test user LTest / Lab Test to the Domain Admins group in Active Directory Users and Computers. After applying the group membership change, I searched Splunk for Windows Security Event ID `4728` on DC01.

The raw event confirmed that a member was added to a security-enabled global group. The event showed that the actor account was Administrator, the added member was Lab Test, and the modified group was `Domain Admins`.

This activity is high risk because adding a user to Domain Admins can grant broad administrative access across the domain. In a real SOC investigation, I would confirm whether the change was authorized, review related account management activity, and check whether the newly privileged account was used for logon activity.

## Severity

High

Adding a user to `Domain Admins` should be treated as high severity unless it is confirmed to be authorized administrative activity.

## False Positive Considerations

- Approved administrator maintenance
- Authorized user provisioning
- Lab-generated testing
- Temporary privileged access assignment
- Help desk or identity management workflow

This detection becomes more suspicious when the actor account is unusual, the change occurs outside normal hours, the added account is newly created, or the account logs in shortly after being added.

## Recommended Response

- Confirm whether the group change was authorized.
- Identify the actor account that made the change.
- Review the added user’s account details.
- Check whether the added user logged in after being added to the group.
- Review additional account management events from the same actor.
- Remove the user from the privileged group if unauthorized.
- Reset credentials if compromise is suspected.
- Document the full timeline of the group membership change.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Lab Test added to Domain Admins in Active Directory Users and Computers | <img width="624" height="360" alt="05_aduc_privileged_group_change" src="https://github.com/user-attachments/assets/5ef712d5-a304-4b7e-8453-982d89438bf1" /> |
| Raw Event ID 4728 group membership change in Splunk | <img width="624" height="330" alt="05_raw_4728_group_change_event" src="https://github.com/user-attachments/assets/bb9ccbd8-deba-4e74-94e4-31866819c4c7" /> |
| Splunk detection showing privileged group change | <img width="624" height="402" alt="05_privileged_group_change_detection" src="https://github.com/user-attachments/assets/1d22b09a-8ce2-4d17-b2bc-4126afe7416a" /> |

## Analyst Conclusion

This detection successfully identified a privileged Active Directory group membership change. The test user `LTest` / `Lab Test` was added to the `Domain Admins` group, and Splunk detected the activity using Windows Security Event ID `4728`.

This detection is important because unauthorized privileged group changes can indicate privilege escalation, persistence, or account compromise. In a real investigation, this alert would require immediate validation and review of any follow-on activity by the newly privileged account.
