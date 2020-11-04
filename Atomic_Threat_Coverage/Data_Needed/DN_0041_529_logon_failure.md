| Title              | DN_0041_529_logon_failure       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Logon Failure - Unknown user name or bad password |
| **Logging Policy** | <ul><li>[LP0004_windows_audit_logon](../Logging_Policies/LP0004_windows_audit_logon.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=529](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=529)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>Reason</li><li>UserName</li><li>Domain</li><li>LogonType</li><li>LogonProcess</li><li>AuthenticationPackage</li><li>WorkstationName</li><li>CallerUserName</li><li>CallerDomain</li><li>CallerLogonID</li><li>CallerProcessID</li><li>TransitedServices</li><li>SourceNetworkAddress</li><li>SourcePort</li></ul> |


## Log Samples

### Raw Log

```
2019-07-15 22:00:20 ATC AUDIT_FAILURE 529 NT AUTHORITY\SYSTEM Logon Failure:
  Reason:   Unknown user name or bad password
  User Name:  asdfasd
  Domain:   ATC
  Logon Type: 10
  Logon Process:  User32  
  Authentication Package: Negotiate
  Workstation Name: ATC
  Caller User Name: ATC$
  Caller Domain:  WORKGROUP
  Caller Logon ID:  (0x0,0x3E7)
  Caller Process ID:  3064
  Transited Services: -
  Source Network Address: 192.168.88.198
  Source Port:  52013

```




