| Title          | LP_0025_audit_directory_service_changes                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Audit Directory Service Changes determines whether  the operating system generates audit events when changes  are made to objects in Active Directory Domain Services (AD DS).                                                               |
| Default        | Partially (Other)                                                                   |
| Event Volume   | High on domain controllers                                                                    |
| EventID        | <ul><li>5136</li><li>5137</li><li>5138</li><li>5139</li><li>5141</li></ul>         |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-directory-service-changes.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/audit-directory-service-changes.md)</li></ul> |



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
Audit Directory Service Changes (Success,Failure)
```


