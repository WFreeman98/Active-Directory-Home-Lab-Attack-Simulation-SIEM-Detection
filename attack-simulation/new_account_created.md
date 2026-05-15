# Detection 04: New Account Created

## Objective

Detect the creation of a new Active Directory domain user account.

This detection identifies Windows Security Event ID 4720, which is generated when a new user account is created. In this lab, a new domain user account named `LTest` was created in Active Directory Users and Computers on DC01.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | T1136.002 - Create Account: Domain Account | A new Active Directory domain user account was created. |
| Privilege Escalation | T1136.002 - Create Account: Domain Account | Unauthorized account creation may allow an attacker to maintain or expand access. |

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 4720
- Domain Controller: DC01

## Detection Logic

This detection looks for Event ID `4720` on the domain controller.

A new account creation event should be reviewed because attackers may create new accounts for persistence, privilege escalation, or future access. In an enterprise environment, new account creation should normally match an approved onboarding or administrative request.

## SPL Query

```spl
index=endpoint host="DC01" EventCode=4720 LTest
| eval creator=mvindex(Account_Name,0)
| eval created_user=mvindex(Account_Name,1)
| table _time EventCode host ComputerName created_user creator TargetDomainName
| sort -_time
```

## Attack Simulation

A new domain user account was created in Active Directory Users and Computers on DC01.

Created account:

```text
LTest
```

The account was created through:

```text
Active Directory Users and Computers
```

This generated Windows Security Event ID `4720` on the domain controller.

## Detection Result

Splunk detected Event ID `4720` on DC01 after the new user account was created.

The event showed:

```text
Created user: LTest
Creator: Administrator
Host: DC01
Event ID: 4720
```

## Analyst Thought Process

### Initial Alert Meaning

A new domain account was created. This may be legitimate administrative activity, but it can also indicate attacker persistence if the account was created without authorization.

### Key Questions

- What account was created?
- Who created the account?
- Was the account creation approved?
- Was the account added to any privileged groups?
- Was the account used to log in after creation?
- Did the same creator account perform any other suspicious activity?

### Evidence Reviewed

- Event ID 4720
- Created user: LTest
- Creator account: Administrator
- Host: DC01
- Domain: corp.local

## Analyst Investigation Summary

I began by creating a new test domain user account in Active Directory Users and Computers. After the account was created, I searched Splunk for Windows Security Event ID 4720 on DC01.

The raw event confirmed that a new account was created. I then cleaned the fields in Splunk to identify the created account and the account responsible for creating it. The created account was `LTest`, and the creator account was `Administrator`.

In a real SOC investigation, I would verify whether the account creation was expected and approved. I would also check whether the account was added to privileged groups, used for logon activity, or involved in any follow-on activity.

## Severity

Medium

Increase to High if the account was created by an unexpected user, added to a privileged group, or used for suspicious logon activity.

## False Positive Considerations

- Normal user onboarding
- Help desk account creation
- Administrator testing
- Lab-generated account creation
- Service or temporary account creation

This detection becomes more suspicious when the creator account is unusual, the account is created outside normal business hours, or the new account is quickly added to privileged groups.

## Recommended Response

- Confirm whether the account creation was authorized.
- Identify the creator account.
- Review the new account’s group memberships.
- Check for successful logons by the new account.
- Review recent account management events from the same creator.
- Disable the account if it was not authorized.
- Document the full account creation timeline.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| New account created in Active Directory Users and Computers | <img width="563" height="468" alt="04_net_user_account_created" src="https://github.com/user-attachments/assets/da9a516d-e7f2-4ee7-a880-98070adb571e" /> |
| Raw Event ID 4720 new account creation event in Splunk | <img width="624" height="137" alt="04_raw_4720_new_account_event" src="https://github.com/user-attachments/assets/d3420c64-52c2-46e3-98fb-e9ffaa55476d" /> |
| Splunk detection showing created user and creator account | <img width="624" height="146" alt="04_new_account_created_detection" src="https://github.com/user-attachments/assets/ffae2dfa-7a8e-4d08-aa58-504f26e4123c" /> |

## Analyst Conclusion

This detection successfully identified the creation of a new Active Directory domain user account. The account `LTest` was created on DC01, and Splunk detected the activity using Windows Security Event ID 4720.

This detection is important because unauthorized account creation can be used for persistence or privilege escalation. In a real investigation, the next steps would be to confirm whether the account creation was approved, review group membership changes, and check for successful logons by the new account.
