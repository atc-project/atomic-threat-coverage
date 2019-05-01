| Title                | Suspicious Driver Load from Temp                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a driver load from a temporary directory                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>there is a relevant set of false positives depending on applications in the environment</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Driver Load from Temp
description: Detects a driver load from a temporary directory
author: Florian Roth
tags: 
  - attack.persistence
  - attack.t1050
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
        ImageLoaded: '*\Temp\\*'
    condition: selection
falsepositives:
    - there is a relevant set of false positives depending on applications in the environment 
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
(EventID:"6" AND ImageLoaded:"*\\\\Temp\\\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*6)(?=.*.*\\Temp\\\\.*))'
```



