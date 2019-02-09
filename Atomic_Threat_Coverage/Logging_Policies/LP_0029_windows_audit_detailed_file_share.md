| Title          | LP_0029_windows_audit_detailed_file_share                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Detailed File Share allows you to audit attempts to  access files and folders on a shared folder.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | High on file servers and domain controllers                                                                    |
| EventID        | <ul><li>5145</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-detailed-file-share.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-detailed-file-share.md)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Object Access > 
Audit Detailed File Share (Success,Failure)
```


