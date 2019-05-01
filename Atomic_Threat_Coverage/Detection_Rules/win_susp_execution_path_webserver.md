| Title                | Execution in Webserver Root Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious program execution in a web service root folder (filter out false positives)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Various applications</li><li>Tools that include ping or nslookup command invocations</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Execution in Webserver Root Folder
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
tags:
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wwwroot\\*'
            - '*\wmpub\\*'
            - '*\htdocs\\*'
    filter:
        Image:
            - '*bin\\*'
            - '*\Tools\\*'
            - '*\SMSComponent\\*'
        ParentImage:
            - '*\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(Image:("*\\\\wwwroot\\\\*" "*\\\\wmpub\\\\*" "*\\\\htdocs\\\\*") AND NOT (Image:("*bin\\\\*" "*\\\\Tools\\\\*" "*\\\\SMSComponent\\\\*") AND ParentImage:("*\\\\services.exe")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wwwroot\\\\.*|.*.*\\wmpub\\\\.*|.*.*\\htdocs\\\\.*))(?=.*(?!.*(?:.*(?=.*(?:.*.*bin\\\\.*|.*.*\\Tools\\\\.*|.*.*\\SMSComponent\\\\.*))(?=.*(?:.*.*\\services\\.exe))))))'
```



