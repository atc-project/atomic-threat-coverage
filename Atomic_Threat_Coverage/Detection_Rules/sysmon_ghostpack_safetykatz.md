| Title                | Detection of SafetyKatz                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects possible SafetyKatz Behaviour                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Detection of SafetyKatz
status: experimental
description: Detects possible SafetyKatz Behaviour
references:
    - https://github.com/GhostPack/SafetyKatz
tags:
    - attack.credential_access
    - attack.t1003
author: Markus Neis
date: 2018/07/24
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename: '*\Temp\debug.bin'
    condition: selection
falsepositives:
    - Unknown
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
(EventID:"11" AND TargetFilename:"*\\\\Temp\\\\debug.bin")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\\Temp\\debug\\.bin))'
```



