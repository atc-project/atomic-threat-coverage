| Title                | Usage of Sysinternals Tools                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage of Sysinternals Tools due to accepteula key beeing added to Registry                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Legitimate use of SysInternals tools</li><li>Programs that use the same Registry Key</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/Moti_B/status/1008587936735035392](https://twitter.com/Moti_B/status/1008587936735035392)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Usage of Sysinternals Tools 
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key beeing added to Registry 
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
author: Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: '*\EulaAccepted'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        CommandLine: '* -accepteula*'
```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\EulaAccepted")\nCommandLine:"* \\-accepteula*"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\EulaAccepted))'\ngrep -P '^.* -accepteula.*'
```



