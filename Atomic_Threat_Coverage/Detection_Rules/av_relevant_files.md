| Title                | Antivirus Relevant File Paths Alerts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an Antivirus alert in a highly relevant file path or with a relevant file name                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unlikely</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Antivirus Relevant File Paths Alerts
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name
date: 2018/09/09
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
logsource:
    product: antivirus
detection:
    selection:
        FileName:
            - 'C:\Windows\Temp\\*'
            - 'C:\Temp\\*'
            - '*\\Client\\*'
            - 'C:\PerfLogs\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
            - '*.ps1'
            - '*.vbs'
            - '*.bat'
            - '*.chm'
            - '*.xml'
            - '*.txt'
            - '*.jsp'
            - '*.jspx'
            - '*.asp'
            - '*.aspx'
            - '*.php'
            - '*.war'
    condition: selection
fields:
    - Signature
    - User
falsepositives:
    - Unlikely
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
FileName:("C\\:\\\\Windows\\\\Temp\\\\*" "C\\:\\\\Temp\\\\*" "*\\\\Client\\\\*" "C\\:\\\\PerfLogs\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*" "*.ps1" "*.vbs" "*.bat" "*.chm" "*.xml" "*.txt" "*.jsp" "*.jspx" "*.asp" "*.aspx" "*.php" "*.war")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*C:\\Windows\\Temp\\\\.*|.*C:\\Temp\\\\.*|.*.*\\\\Client\\\\.*|.*C:\\PerfLogs\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*|.*.*\\.ps1|.*.*\\.vbs|.*.*\\.bat|.*.*\\.chm|.*.*\\.xml|.*.*\\.txt|.*.*\\.jsp|.*.*\\.jspx|.*.*\\.asp|.*.*\\.aspx|.*.*\\.php|.*.*\\.war)'
```



