| Title            | LP_0037_windows_audit_audit_policy_change                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | This policy determines whether the operating system generates  audit events when changes are made to audit policy                                                               |
| **Default**      | Partially (Success)                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4902</li><li>4907</li><li>4904</li><li>4905</li><li>4715</li><li>4719</li><li>4817</li><li>4902</li><li>4906</li><li>4907</li><li>4908</li><li>4912</li><li>4904</li><li>4905</li></ul>         |
| **References**   | <ul><li>[https://technet.microsoft.com/en-us/library/dn319116(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/dn319116(v=ws.11).aspx)</li><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-audit-policy-change.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-audit-policy-change.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Policy Change >
Audit Audit Policy Change (Success,Failure)
```

Script to implement logging policy:

```
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
```


