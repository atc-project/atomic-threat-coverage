| Title          | LP_0026_windows_audit_user_account_management                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit User Account Management determines whether the operating  system generates audit events when specific user account  management tasks are performed.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | Low                                                                    |
| EventID        | <ul><li>4720</li><li>4722</li><li>4723</li><li>4724</li><li>4725</li><li>4726</li><li>4738</li><li>4740</li><li>4765</li><li>4766</li><li>4767</li><li>4780</li><li>4781</li><li>4794</li><li>4798</li><li>5376</li><li>5377</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-user-account-management.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-user-account-management.md)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
Account Management > 
Audit User Account Management (Success,Failure)
```


