| Title                | Malicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords from well-known PowerShell exploitation frameworks                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>                                                          |
| Author               | Sean Metcalf (source), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Malicious PowerShell Keywords
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
    definition: 'It is recommanded to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        - AdjustTokenPrivileges
        - IMAGE_NT_OPTIONAL_HDR64_MAGIC
        - Microsoft.Win32.UnsafeNativeMethods
        - ReadProcessMemory.Invoke
        - SE_PRIVILEGE_ENABLED
        - LSA_UNICODE_STRING
        - MiniDumpWriteDump
        - PAGE_EXECUTE_READ
        - SECURITY_DELEGATION
        - TOKEN_ADJUST_PRIVILEGES
        - TOKEN_ALL_ACCESS
        - TOKEN_ASSIGN_PRIMARY
        - TOKEN_DUPLICATE
        - TOKEN_ELEVATION
        - TOKEN_IMPERSONATE
        - TOKEN_INFORMATION_CLASS
        - TOKEN_PRIVILEGES
        - TOKEN_QUERY
        - Metasploit
        - Mimikatz
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
("AdjustTokenPrivileges" OR "IMAGE_NT_OPTIONAL_HDR64_MAGIC" OR "Microsoft.Win32.UnsafeNativeMethods" OR "ReadProcessMemory.Invoke" OR "SE_PRIVILEGE_ENABLED" OR "LSA_UNICODE_STRING" OR "MiniDumpWriteDump" OR "PAGE_EXECUTE_READ" OR "SECURITY_DELEGATION" OR "TOKEN_ADJUST_PRIVILEGES" OR "TOKEN_ALL_ACCESS" OR "TOKEN_ASSIGN_PRIMARY" OR "TOKEN_DUPLICATE" OR "TOKEN_ELEVATION" OR "TOKEN_IMPERSONATE" OR "TOKEN_INFORMATION_CLASS" OR "TOKEN_PRIVILEGES" OR "TOKEN_QUERY" OR "Metasploit" OR "Mimikatz")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*AdjustTokenPrivileges|.*IMAGE_NT_OPTIONAL_HDR64_MAGIC|.*Microsoft\\.Win32\\.UnsafeNativeMethods|.*ReadProcessMemory\\.Invoke|.*SE_PRIVILEGE_ENABLED|.*LSA_UNICODE_STRING|.*MiniDumpWriteDump|.*PAGE_EXECUTE_READ|.*SECURITY_DELEGATION|.*TOKEN_ADJUST_PRIVILEGES|.*TOKEN_ALL_ACCESS|.*TOKEN_ASSIGN_PRIMARY|.*TOKEN_DUPLICATE|.*TOKEN_ELEVATION|.*TOKEN_IMPERSONATE|.*TOKEN_INFORMATION_CLASS|.*TOKEN_PRIVILEGES|.*TOKEN_QUERY|.*Metasploit|.*Mimikatz))'
```



