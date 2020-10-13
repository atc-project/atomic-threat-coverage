| Title              | DN_0042_675_kerberos_preauthentication_failed       |
|:-------------------|:------------------|
| **Description**    | Kerberos pre-authentication failed |
| **Logging Policy** | <ul><li>[LP_0004_windows_audit_logon](../Logging_Policies/LP_0004_windows_audit_logon.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=675](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=675)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>UserName</li><li>UserID</li><li>UserSid</li><li>ServiceName</li><li>PreAuthenticationType</li><li>FailureCode</li><li>ClientAddress</li></ul> |


## Log Samples

### Raw Log

```
2019-07-18 00:56:03 ATC AUDIT_FAILURE 675 NT AUTHORITY\SYSTEM Pre-authentication failed:
  User Name:  Administrator
  User ID:    %{S-1-5-21-3160476663-3818360063-188177334-500}
  Service Name: krbtgt/DC
  Pre-Authentication Type:  0x2
  Failure Code: 0x18
  Client Address: 127.0.0.1

```




