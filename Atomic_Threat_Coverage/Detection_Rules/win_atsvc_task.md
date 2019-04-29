| Title                | Remote Task Creation via ATSVC named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote task creation via at.exe or API interacting with ATSVC namedpipe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>pentesting</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html](https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Remote Task Creation via ATSVC named pipe
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1053
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: atsvc
        Accesses: '*WriteData*'
    condition: selection
falsepositives: 
    - pentesting
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:"atsvc" AND Accesses:"*WriteData*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*atsvc)(?=.*.*WriteData.*))'
```



