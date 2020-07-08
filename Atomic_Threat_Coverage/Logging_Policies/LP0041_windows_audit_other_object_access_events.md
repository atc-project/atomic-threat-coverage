| Title            | LP0041_windows_audit_other_object_access_events                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | This security policy setting determines whether the operating system generates  audit events for the management of Task Scheduler jobs or COM+ objects                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Medium                                                                    |
| **EventID**      | <ul><li>4671</li><li>4691</li><li>5148</li><li>5149</li><li>4698</li><li>4699</li><li>4700</li><li>4701</li><li>4702</li><li>5888</li><li>5889</li><li>5890</li></ul>         |
| **References**   | <ul><li>[https://technet.microsoft.com/en-us/library/dd772744(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/dd772744(v=ws.10).aspx)</li><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-other-object-access-events.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/audit-other-object-access-events.md)</li></ul> |



## Configuration

Manual steps to implement logging policy:

```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Audit Policy Configuration >
Audit Policies >
Object Access >
Audit Other Object Access Events (Success)
```

Script to implement logging policy:

```
Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:disable
```

