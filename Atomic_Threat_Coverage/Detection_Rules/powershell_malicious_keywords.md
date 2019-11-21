| Title                | Malicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords from well-known PowerShell exploitation frameworks                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| Author               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious PowerShell Keywords
id: f62176f3-8128-4faa-bf6c-83261322e5eb
status: experimental
description: Detects keywords from well-known PowerShell exploitation frameworks
modified: 2019/01/22
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        Message:
            - "*AdjustTokenPrivileges*"
            - "*IMAGE_NT_OPTIONAL_HDR64_MAGIC*"
            - "*Microsoft.Win32.UnsafeNativeMethods*"
            - "*ReadProcessMemory.Invoke*"
            - "*SE_PRIVILEGE_ENABLED*"
            - "*LSA_UNICODE_STRING*"
            - "*MiniDumpWriteDump*"
            - "*PAGE_EXECUTE_READ*"
            - "*SECURITY_DELEGATION*"
            - "*TOKEN_ADJUST_PRIVILEGES*"
            - "*TOKEN_ALL_ACCESS*"
            - "*TOKEN_ASSIGN_PRIMARY*"
            - "*TOKEN_DUPLICATE*"
            - "*TOKEN_ELEVATION*"
            - "*TOKEN_IMPERSONATE*"
            - "*TOKEN_INFORMATION_CLASS*"
            - "*TOKEN_PRIVILEGES*"
            - "*TOKEN_QUERY*"
            - "*Metasploit*"
            - "*Mimikatz*"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### splunk
    
```
(Message="*AdjustTokenPrivileges*" OR Message="*IMAGE_NT_OPTIONAL_HDR64_MAGIC*" OR Message="*Microsoft.Win32.UnsafeNativeMethods*" OR Message="*ReadProcessMemory.Invoke*" OR Message="*SE_PRIVILEGE_ENABLED*" OR Message="*LSA_UNICODE_STRING*" OR Message="*MiniDumpWriteDump*" OR Message="*PAGE_EXECUTE_READ*" OR Message="*SECURITY_DELEGATION*" OR Message="*TOKEN_ADJUST_PRIVILEGES*" OR Message="*TOKEN_ALL_ACCESS*" OR Message="*TOKEN_ASSIGN_PRIMARY*" OR Message="*TOKEN_DUPLICATE*" OR Message="*TOKEN_ELEVATION*" OR Message="*TOKEN_IMPERSONATE*" OR Message="*TOKEN_INFORMATION_CLASS*" OR Message="*TOKEN_PRIVILEGES*" OR Message="*TOKEN_QUERY*" OR Message="*Metasploit*" OR Message="*Mimikatz*")
```



