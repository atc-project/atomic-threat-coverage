| Title              | DN0040_528_user_successfully_logged_on_to_a_computer       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | User successfully logged on to a computer |
| **Logging Policy** | <ul><li>[LP0004_windows_audit_logon](../Logging_Policies/LP0004_windows_audit_logon.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=528](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=528)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>UserName</li><li>Domain</li><li>LogonID</li><li>LogonType</li><li>LogonProcess</li><li>AuthenticationPackage</li><li>WorkstationName</li><li>LogonGUID</li><li>CallerUserName</li><li>CallerDomain</li><li>CallerLogonID</li><li>CallerProcessID</li><li>TransitedServices</li><li>SourceNetworkAddress</li><li>SourcePort</li></ul> |


## Log Samples

### Raw Log

```
2019-07-15 21:44:17 ATC AUDIT_SUCCESS 528 ATC\Administrator Successful Logon:
  User Name:  Administrator
  Domain:   ATC
  Logon ID:   (0x0,0x5A53F)
  Logon Type: 2
  Logon Process:  User32  
  Authentication Package: Negotiate
  Workstation Name: ATC
  Logon GUID: -
  Caller User Name: ATC$
  Caller Domain:  WORKGROUP
  Caller Logon ID:  (0x0,0x3E7)
  Caller Process ID: 380
  Transited Services: -
  Source Network Address: 127.0.0.1
  Source Port:  0

```




