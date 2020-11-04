| Title            | LP_0038_windows_audit_kerberos_authentication_service                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Kerberos Authentication Service determines whether to generate  audit events for Kerberos authentication ticket-granting ticket (TGT) requests                                                               |
| **Default**      | Partially (Other)                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>4768</li><li>4771</li><li>4772</li></ul>         |
| **References**   | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter4#KAS](https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter4#KAS)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service)</li><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kerberos-authentication-service.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-kerberos-authentication-service.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Account Logon >
Audit Kerberos Authentication Service (Success,Failure)
```

Script to implement logging policy:

```
Auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

