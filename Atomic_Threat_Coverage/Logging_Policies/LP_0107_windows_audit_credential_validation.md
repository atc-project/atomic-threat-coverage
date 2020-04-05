| Title            | LP_0107_windows_audit_credential_validation                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | Audit Credential Validation determines whether the operating system  generates audit events on credentials that are submitted for a user  account logon request                                                               |
| **Default**      | Configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>4774</li><li>4775</li><li>4776</li><li>4777</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-credential-validation.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-credential-validation.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Account Logon >
Audit Credential Validation (Success,Failure)
```


