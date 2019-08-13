| Title                 | HP_0001_windows_LocalAccountTokenFilterPolicy                                                                          |
|:----------------------|:-------------------------------------------------------------------------------------|
| Description           | This Hardening Policy applies UAC token-filtering to local accounts on network logons.  Membership in powerful group such as Administrators is disabled and powerful privileges are  removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy  registry value to 0. This is the default behavior for Windows                                                                    |
| ATT&amp;CK Tactic     | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique  | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| ATT&amp;CK Mitigation | <ul><li>[M1052: User Account Control](https://attack.mitre.org/mitigations/M1052)</li></ul>  |
| Platform              | <ul><li>Windows</li></ul>                   |
| Minimum Version       | <ul><li>Windows Vista</li><li>Windows Server 2008</li></ul>      |
| References            | <ul><li>[https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows](https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows)</li><li>[https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)</li><li>[https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/](https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)</li><li>[https://github.com/nsacyber/Windows-Secure-Host-Baseline/blob/master/Windows/Group%20Policy%20Templates/en-US/SecGuide.adml](https://github.com/nsacyber/Windows-Secure-Host-Baseline/blob/master/Windows/Group%20Policy%20Templates/en-US/SecGuide.adml)</li></ul>      |


## Configuration

Steps to implement hardening policy with GPO (requires security baselines download and place into `%SystemRoot%\PolicyDefinitions`):
```
Computer Configuration > 
Administrative Templates > 
SCM: Pass the Hash Mitigations >
Apply UAC restrictions to local accounts on network logons
```

Enabling via registry key:
```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
```