| Title          | LP_0004_windows_audit_logon                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Logon determines whether the operating system generates audit  events when a user attempts to log on to a computer.                                                               |
| Default        | Partially (Success)                                                                   |
| Event Volume   | Medium                                                                    |
| EventID        | <ul><li>4624</li><li>4625</li><li>4648</li><li>4675</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-logon.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-logon.md)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Logon/Logoff
Audit logon (Success,Failure)
```


