| Title                | Hijack legit RDP session to move laterally                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Hijack legit RDP session to move laterally  
status: experimental
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
date: 2019/02/21
author: Samir Bousseaden
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        Image: '*\mstsc.exe'
        TargetFileName: '*\Microsoft\Windows\Start Menu\Programs\Startup\*'
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
(EventID:"11" AND Image:"*\\\\mstsc.exe" AND TargetFileName:"*\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\\mstsc\\.exe)(?=.*.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*))'
```



