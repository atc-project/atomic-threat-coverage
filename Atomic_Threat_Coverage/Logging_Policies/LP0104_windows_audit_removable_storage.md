| Title            | LP0104_windows_audit_removable_storage                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Removable Storage allows you to audit user attempts to access file  system objects on a removable storage device. A security audit event is  generated for all objects and all types of access requested, with no  dependency on object’s SACL                                                               |
| **Default**      | Configured                                                                   |
| **Event Volume** | Medium                                                                    |
| **EventID**      | <ul><li>4656</li><li>4658</li><li>4663</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-removable-storage.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-removable-storage.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Object Access >
Audit Removable Storage (Success, Failure)
```


