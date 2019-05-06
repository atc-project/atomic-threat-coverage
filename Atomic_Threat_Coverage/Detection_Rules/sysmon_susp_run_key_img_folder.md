| Title                | New RUN Key Pointing to Suspicious Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious new RUN key element pointing to an executable in a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Software with rare behaviour</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</li></ul>                                                          |
| Author               | Florian Roth, Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: New RUN Key Pointing to Suspicious Folder
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth, Markus Neis
tags:
    - attack.persistence
    - attack.t1060
date: 2018/25/08
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*'
        Details:
          - 'C:\Windows\Temp\\*'
          - '*\AppData\\*'
          - 'C:\$Recycle.bin\\*'
          - 'C:\Temp\\*'
          - 'C:\Users\Public\\*'
          - 'C:\Users\Default\\*'
          - 'C:\Users\Desktop\\*'
    condition: selection
fields:
    - Image
falsepositives:
    - Software with rare behaviour
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
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*") AND Details:("C\\:\\\\Windows\\\\Temp\\\\*" "*\\\\AppData\\\\*" "C\\:\\\\$Recycle.bin\\\\*" "C\\:\\\\Temp\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*" "C\\:\\\\Users\\\\Desktop\\\\*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\\\.*|.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\\\.*))(?=.*(?:.*C:\\Windows\\Temp\\\\.*|.*.*\\AppData\\\\.*|.*C:\\\\$Recycle\\.bin\\\\.*|.*C:\\Temp\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*|.*C:\\Users\\Desktop\\\\.*)))'
```



