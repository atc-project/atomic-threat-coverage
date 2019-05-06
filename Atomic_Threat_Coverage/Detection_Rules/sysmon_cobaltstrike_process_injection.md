| Title                | CobaltStrike Process Injection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f](https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f)</li></ul>                                                          |
| Author               | Olaf Hartong, Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: CobaltStrike Process Injection 
description: Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons 
references:
    - https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
tags:
    - attack.defense_evasion
    - attack.t1055
status: experimental
author: Olaf Hartong, Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetProcessAddress: '*0B80'
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
(EventID:"8" AND TargetProcessAddress:"*0B80")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*.*0B80))'
```



