| Title                | Suspicious Program Location with Network Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs with network connections running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location with Network Connections
status: experimental
description: Detects programs with network connections running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
author: Florian Roth
date: 2017/03/19
logsource:
    product: windows
    service: sysmon
    definition: 'Use the following config to generate the necessary Event ID 3 Network Connection events'
detection:
    selection:
        EventID: 3
        Image: 
            # - '*\ProgramData\\*'  # too many false positives, e.g. with Webex for Windows
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - '*\Users\Contacts\\*'
            - '*\Users\Searches\\*' 
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
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
(EventID:"3" AND Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\All Users\\\\*" "*\\\\Users\\\\Default\\\\*" "*\\\\Users\\\\Public\\\\*" "*\\\\Users\\\\Contacts\\\\*" "*\\\\Users\\\\Searches\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\config\\\\systemprofile\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\\\$Recycle\\.bin|.*.*\\Users\\All Users\\\\.*|.*.*\\Users\\Default\\\\.*|.*.*\\Users\\Public\\\\.*|.*.*\\Users\\Contacts\\\\.*|.*.*\\Users\\Searches\\\\.*|.*C:\\Perflogs\\\\.*|.*.*\\config\\systemprofile\\\\.*|.*.*\\Windows\\Fonts\\\\.*|.*.*\\Windows\\IME\\\\.*|.*.*\\Windows\\addins\\\\.*)))'
```



