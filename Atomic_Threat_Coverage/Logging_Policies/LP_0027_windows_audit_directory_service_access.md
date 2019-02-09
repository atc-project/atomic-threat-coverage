| Title          | LP_0027_windows_audit_directory_service_access                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Directory Service Access determines whether the operating  system generates audit events when an Active Directory Domain  Services (AD DS) object is accessed.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | High on domain controllers                                                                    |
| EventID        | <ul><li>4662</li><li>4661</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-directory-service-access.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-directory-service-access.md)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
DS Access > 
Audit Directory Service Access (Success,Failure)
```


