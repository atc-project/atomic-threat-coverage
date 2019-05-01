| Title                | SAM Dump to AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration testing</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: SAM Dump to AppData
status: experimental
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
tags:
    - attack.credential_access
    - attack.t1003
author: Florian Roth
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        EventID: 16
    keywords:
        - '*\AppData\Local\Temp\SAM-*.dmp *'
    condition: all of them
falsepositives:
    - Penetration testing
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
(EventID:"16" AND "*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp *")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*16)(?=.*.*\\AppData\\Local\\Temp\\SAM-.*\\.dmp .*))'
```



