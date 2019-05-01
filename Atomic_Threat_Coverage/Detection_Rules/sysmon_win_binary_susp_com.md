| Title                | Microsoft Binary Suspicious Communication Endpoint                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the Windows folder accessing suspicious domains                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Suspicious Communication Endpoint
status: experimental
description: Detects an executable in the Windows folder accessing suspicious domains
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Florian Roth
date: 2018/08/30
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
            - '*dl.dropboxusercontent.com'
            - '*.pastebin.com'
        Image: 'C:\Windows\\*'
    condition: selection
falsepositives:
    - 'Unknown'
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
(EventID:"3" AND DestinationHostname:("*dl.dropboxusercontent.com" "*.pastebin.com") AND Image:"C\\:\\\\Windows\\\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*dl\\.dropboxusercontent\\.com|.*.*\\.pastebin\\.com))(?=.*C:\\Windows\\\\.*))'
```



