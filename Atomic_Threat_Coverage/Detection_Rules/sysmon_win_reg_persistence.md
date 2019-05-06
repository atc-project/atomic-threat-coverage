| Title                | Registry Persistence Mechanisms                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects persistence registry keys                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1183: Image File Execution Options Injection](https://attack.mitre.org/techniques/T1183)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1183: Image File Execution Options Injection](../Triggers/T1183.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)</li></ul>                                                          |
| Author               | Karneades                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Registry Persistence Mechanisms
description: Detects persistence registry keys 
references:
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
date: 2018/04/11
author: Karneades
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg1:
        EventID: 13 
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\*\GlobalFlag'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\ReportingMode'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\MonitorProcess'
        EventType: 'SetValue'
    condition: selection_reg1
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.defense_evasion
    - attack.t1183
falsepositives:
    - unknown
level: critical

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\*\\\\GlobalFlag" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\ReportingMode" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SilentProcessExit\\\\*\\\\MonitorProcess") AND EventType:"SetValue")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\\\.*\\GlobalFlag|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\\\.*\\ReportingMode|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\\\.*\\MonitorProcess))(?=.*SetValue))'
```



