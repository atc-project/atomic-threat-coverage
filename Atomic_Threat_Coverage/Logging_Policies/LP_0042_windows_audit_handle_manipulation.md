| Title            | LP_0042_windows_audit_handle_manipulation                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | This security policy setting determines whether the operating system  generates audit events when a handle to an object is opened or closed.  Policy to enable smb share access logon events logging                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>4658</li><li>4690</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-handle-manipulation.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-handle-manipulation.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Handle Manipulation (Success,Failure)
```

Script to implement logging policy:

```
Auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

