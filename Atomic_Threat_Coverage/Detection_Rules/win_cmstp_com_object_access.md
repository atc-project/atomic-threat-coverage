| Title                | CMSTP UAC Bypass via COM Object Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li><li>[T1191: CMSTP](../Triggers/T1191.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Legitimate CMSTP use (unlikely in modern enterprise environments)</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/](http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/)</li><li>[https://twitter.com/hFireF0X/status/897640081053364225](https://twitter.com/hFireF0X/status/897640081053364225)</li></ul>                                                          |
| Author               | Nik Seetharaman                                                                                                                                                |
| Other Tags           | <ul><li>attack.g0069</li><li>attack.g0069</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CMSTP UAC Bypass via COM Object Access
status: stable
description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.execution
    - attack.t1088
    - attack.t1191
    - attack.g0069
author: Nik Seetharaman
references:
    - http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
    - https://twitter.com/hFireF0X/status/897640081053364225
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentCommandLine: '*\DllHost.exe'
    selection2:
        ParentCommandLine:
            - '*\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
            - '*\{3E000D72-A845-4CD9-BD83-80C07C3B881F}'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentCommandLine
    - Hashes
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
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
(ParentCommandLine:"*\\\\DllHost.exe" AND ParentCommandLine:("*\\\\\\{3E5FC7F9\\-9A51\\-4367\\-9063\\-A120244FBEC7\\}" "*\\\\\\{3E000D72\\-A845\\-4CD9\\-BD83\\-80C07C3B881F\\}"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\DllHost\\.exe)(?=.*(?:.*.*\\\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7\\}|.*.*\\\\{3E000D72-A845-4CD9-BD83-80C07C3B881F\\})))'
```



