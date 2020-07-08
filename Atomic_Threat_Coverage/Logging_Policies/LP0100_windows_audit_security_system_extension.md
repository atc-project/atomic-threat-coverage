| Title            | LP0100_windows_audit_security_system_extension                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Security System Extension contains information about the loading of an  authentication package, notification package, or security package, plus  information about trusted logon process registration events                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4610</li><li>4611</li><li>4614</li><li>4622</li><li>4697</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-system-extension](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-system-extension)</li></ul> |



## Configuration

Steps to implement logging policy with Advanced Audit Configuration:
```
Computer Configuration > 
Policies > 
Windows Settings > 
Security Settings > 
Advanced Audit Policies Configuration > 
Audit Policies > 
System > 
Audit Security System Extension (Success)
```


