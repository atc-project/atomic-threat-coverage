| Title            | LP_0044_windows_ntlm_audit                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | This is combined audit policy, consist of 3 policies under "Network security:  Restrict NTLM" — Audit NTLM authentication in this domain, Audit Incoming NTLM Traffic,  Outgoing NTLM traffic to remote servers. It will provide visibility on  NTLM authentication attempts. This policy is only about auditing events, it will not disable NTLM authentication itself.                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>8001</li><li>8002</li><li>8003</li><li>8004</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-incoming-ntlm-traffic](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-incoming-ntlm-traffic)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)</li></ul> |



## Configuration

Steps to implement logging policy with Group Policies:
```
Computer Configuratoin ->
Policies ->
Windows Settings ->
Security Settings ->
Local Policies ->
Security Options:

- Network security: Restrict NTLM: Audit NTLM authentication in this domain: Enable all
- Network security: Restrict NTLM: Audit Incoming NTLM Traffic: Enable audit for all accounts
- Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers. Policy Setting: Audit all
```


