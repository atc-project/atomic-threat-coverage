| Title          | LP_0001_windows_audit_process_creation                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Process Creation determines whether the operating  system generates audit events when a process is created (starts).  These audit events can help you track user activity and understand  how a computer is being used. Information includes the name of the  program or the user that created the process.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | Medium                                                                    |
| EventID        | <ul><li>4688</li><li>4696</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-process-creation.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-process-creation.md)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Configuration >
Detailed Tracking >
Audit Process Creation (Success,Failure)
```


