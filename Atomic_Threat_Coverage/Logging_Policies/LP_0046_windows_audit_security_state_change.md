| Title            | LP_0046_windows_audit_security_state_change                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Security State Change contains Windows startup, recovery,  and shutdown events, and information about changes in system time                                                               |
| **Default**      | Configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4608</li><li>4616</li><li>4621</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-state-change](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-state-change)</li></ul> |



## Configuration

Steps to implement logging policy with Group Policies:
```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
System >
Audit Security State Change (Success)
```


