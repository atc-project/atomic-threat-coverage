| Title                | Microsoft Binary Github Communication                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the Windows folder accessing github.com                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li><li>@subTee in your network</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>                                                          |
| Author               | Michael Haag (idea), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Github Communication
status: experimental
description: Detects an executable in the Windows folder accessing github.com
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Michael Haag (idea), Florian Roth (rule)
tags:
    - attack.lateral_movement
    - attack.t1105
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationHostname: 
            - '*.github.com'
            - '*.githubusercontent.com'
        Image: 'C:\Windows\\*'
    condition: selection
falsepositives:
    - 'Unknown'
    - '@subTee in your network'
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
(EventID:"3" AND DestinationHostname:("*.github.com" "*.githubusercontent.com") AND Image:"C\\:\\\\Windows\\\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\.github\\.com|.*.*\\.githubusercontent\\.com))(?=.*C:\\Windows\\\\.*))'
```



