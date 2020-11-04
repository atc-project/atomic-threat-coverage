| Title            | LP_0105_windows_audit_authorization_policy_change                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Audit Authorization Policy Change allows you to audit assignment and removal  of user rights in user right policies, changes in security token object  permission, resource attributes changes and Central Access Policy changes  for file system objects                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>4703</li><li>4704</li><li>4705</li><li>4670</li><li>4911</li><li>4913</li></ul>         |
| **References**   | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-authorization-policy-change.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-authorization-policy-change.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Policy Change >
Audit Authorization Policy Change (Success,Failure)
```


