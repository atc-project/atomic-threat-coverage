| Title            | LP_0045_windows_audit_filtering_platform_connection                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | Audit Filtering Platform Connection determines whether the operating  system generates audit events when connections are allowed or blocked  by the Windows Filtering Platform                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Extremely High                                                                    |
| **EventID**      | <ul><li>5031</li><li>5150</li><li>5151</li><li>5154</li><li>5155</li><li>5156</li><li>5157</li><li>5158</li><li>5159</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)</li></ul> |



## Configuration

Steps to implement logging policy with Group Policies:
```
Computer Configuration >
Windows Settings >
Security Settings >
Advanced Security Audit Policy Settings >
Audit Policies >
Object Access >
Audit Filtering Platform Connection (Success,Failure)
```


