| Title                | LSASS Memory Dump                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html](https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: LSASS Memory Dump
status: experimental
description: Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
tags:
    - attack.t1003
    - attack.s0002
    - attack.credential_access
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        GrantedAccess: '0x1fffff'
        CallTrace:
         - '*dbghelp.dll*'
         - '*dbgcore.dll*'
    condition: selection
falsepositives:
    - unknown
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
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND GrantedAccess:"0x1fffff" AND CallTrace:("*dbghelp.dll*" "*dbgcore.dll*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*C:\\windows\\system32\\lsass\\.exe)(?=.*0x1fffff)(?=.*(?:.*.*dbghelp\\.dll.*|.*.*dbgcore\\.dll.*)))'
```



