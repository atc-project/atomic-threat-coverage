| Title            | LP_0106_windows_audit_kerberos_service_ticket_operations                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Kerberos Service Ticket Operations determines whether the operating  system generates security audit events for Kerberos service ticket requests. Events are generated every time Kerberos is used to authenticate a user who  wants to access a protected network resource. Kerberos service ticket  operation audit events can be used to track user activity                                                               |
| **Default**      | Partially (Other)                                                                   |
| **Event Volume** | Extremely High                                                                    |
| **EventID**      | <ul><li>4769</li><li>4770</li><li>4773</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Account Logon >
Audit Kerberos Service Ticket Operations (Success,Failure)
```


