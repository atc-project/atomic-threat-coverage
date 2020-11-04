| Title            | LP_0102_windows_audit_file_system                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit File System determines whether the operating system generates audit events when users attempt to access file system objects                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4656</li><li>4658</li><li>4660</li><li>4663</li><li>4664</li><li>4985</li><li>5051</li><li>4670</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-file-system.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-file-system.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit File system (Success, Failure)
```


