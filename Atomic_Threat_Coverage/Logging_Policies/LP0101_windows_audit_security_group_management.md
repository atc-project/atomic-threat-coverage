| Title            | LP0101_windows_audit_security_group_management                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Security Group Management determines whether the operating system generates audit events when specific security group management tasks are performed                                                               |
| **Default**      | Partially (Success)                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4731</li><li>4732</li><li>4733</li><li>4734</li><li>4735</li><li>4764</li><li>4799</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/e7d434a47116a0b49fed43e652a07031d8249ae2/windows/security/threat-protection/auditing/audit-security-group-management.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/e7d434a47116a0b49fed43e652a07031d8249ae2/windows/security/threat-protection/auditing/audit-security-group-management.md)</li></ul> |



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
Audit Security Group Management (Success,Failure)
```


