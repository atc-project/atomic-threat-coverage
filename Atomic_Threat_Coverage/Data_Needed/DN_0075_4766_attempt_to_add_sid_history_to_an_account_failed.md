| Title              | DN_0075_4766_attempt_to_add_sid_history_to_an_account_failed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | An attempt to add SID History to an account failed |
| **Logging Policy** | <ul><li>[LP_0026_windows_audit_user_account_management](../Logging_Policies/LP_0026_windows_audit_user_account_management.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4766](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4766)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>Subject</li><li>SecurityID</li><li>AccountName</li><li>AccountDomain</li><li>LogonID</li><li>TargetAccount</li><li>SecurityID</li><li>AccountName</li><li>AccountDomain</li><li>SourceAccount</li><li>AccountName</li><li>AdditionalInformation</li><li>Privileges</li></ul> |


## Log Samples

### Raw Log

```
An attempt to add SID History to an account failed.
Subject:
Security ID:-
Account Name:%5
Account Domain:%6
Logon ID:%7
Target Account:
Security ID:%4
Account Name:%2
Account Domain:%3
Source Account:
Account Name:%1
Additional Information:
Privileges:%8

```




