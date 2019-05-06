| Title                | Registry Persistence via Explorer Run Key                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible persistence mechanism using RUN key for Windows Explorer and poiting to a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/](https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>capec.270</li><li>capec.270</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Registry Persistence via Explorer Run Key
status: experimental
description: Detects a possible persistence mechanism using RUN key for Windows Explorer and poiting to a suspicious folder
author: Florian Roth
date: 2018/07/18
references:
    - https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Details: 
            - 'C:\Windows\Temp\\*'
            - 'C:\ProgramData\\*'
            - '*\AppData\\*'
            - 'C:\$Recycle.bin\\*'
            - 'C:\Temp\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
    condition: selection
tags:
    - attack.persistence
    - attack.t1060
    - capec.270
fields:
    - Image
    - ParentImage
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
(EventID:"13" AND TargetObject:"*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run" AND Details:("C\\:\\\\Windows\\\\Temp\\\\*" "C\\:\\\\ProgramData\\\\*" "*\\\\AppData\\\\*" "C\\:\\\\$Recycle.bin\\\\*" "C\\:\\\\Temp\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run)(?=.*(?:.*C:\\Windows\\Temp\\\\.*|.*C:\\ProgramData\\\\.*|.*.*\\AppData\\\\.*|.*C:\\\\$Recycle\\.bin\\\\.*|.*C:\\Temp\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*)))'
```



