| Title            | LP0039_windows_audit_kernel_object                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | This policy setting allows you to audit attempts to access the kernel,  which include mutexes and semaphores. Only kernel objects with a matching  system access control list (SACL) generate security audit events                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>4656</li><li>4658</li><li>4660</li><li>4663</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kernel-object.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kernel-object.md)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kernel-object](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kernel-object)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter7](https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter7)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Object Access >
Audit Kernel Object (Success)
```

Script to implement logging policy:

```
Auditpol /set /subcategory:"Kernel Object" /success:enable /failure:disable
```

