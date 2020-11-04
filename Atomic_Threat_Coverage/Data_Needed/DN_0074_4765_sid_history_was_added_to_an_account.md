| Title              | DN_0074_4765_sid_history_was_added_to_an_account       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | SID History was added to an account |
| **Logging Policy** | <ul><li>[LP_0026_windows_audit_user_account_management](../Logging_Policies/LP_0026_windows_audit_user_account_management.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4765](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4765)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>Subject</li><li>SecurityID</li><li>AccountName</li><li>AccountDomain</li><li>LogonID</li><li>TargetAccount</li><li>SecurityID</li><li>AccountName</li><li>AccountDomain</li><li>SourceAccount</li><li>SecurityID</li><li>AccountName</li><li>AdditionalInformation</li><li>Privileges</li><li>SIDList</li></ul> |


## Log Samples

### Raw Log

```
SID History was added to an account.
Subject:
Security ID:%6
Account Name:%7
Account Domain:%8
Logon ID:%9
Target Account:
Security ID:%5
Account Name:%3
Account Domain:%4
Source Account:
Security ID:%2
Account Name:%1
Additional Information:
Privileges:%10
SID List:%11

```




