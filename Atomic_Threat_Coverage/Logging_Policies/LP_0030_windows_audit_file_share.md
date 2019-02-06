| Title          | LP_0030_windows_audit_file_share                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit File Share allows you to audit events related to file  shares: creation, deletion, modification, and access attempts.  Also, it shows failed SMB SPN checks.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | High on file servers and domain controllers                                                                    |
| EventID        | <ul><li>5140</li><li>5142</li><li>5143</li><li>5144</li><li>5168</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-file-share.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-file-share.md)</li></ul> |



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
Audit File Share (Success,Failure)
```


