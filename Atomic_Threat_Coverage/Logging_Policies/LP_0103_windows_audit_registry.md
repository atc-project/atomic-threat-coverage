| Title            | LP_0103_windows_audit_registry                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | Audit Registry allows you to audit attempts to access registry objects.  A security audit event is generated only for objects that have system access  control lists (SACLs) specified, and only if the type of access requested, such  as Read, Write, or Modify, and the account making the request match the  settings in the SACL. If success auditing is enabled, an audit entry is generated each time any account  successfully accesses a registry object that has a matching SACL. If failure auditing  is enabled, an audit entry is generated each time any user unsuccessfully attempts  to access a registry object that has a matching SACL                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Medium                                                                    |
| **EventID**      | <ul><li>4663</li><li>4656</li><li>4658</li><li>4660</li><li>4657</li><li>5039</li><li>4670</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-registry.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-registry.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Registry (Success, Failure)
```


