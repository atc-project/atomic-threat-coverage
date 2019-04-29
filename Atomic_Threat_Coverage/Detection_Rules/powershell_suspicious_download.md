| Title                | Suspicious PowerShell Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell download command                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>PowerShell scripts that download content from the Internet</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Download
status: experimental
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        - 'System.Net.WebClient).DownloadString('
        - 'system.net.webclient).downloadfile('
    condition: keywords
falsepositives:
    - PowerShell scripts that download content from the Internet
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
("System.Net.WebClient\\).DownloadString\\(" OR "system.net.webclient\\).downloadfile\\(")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*System\\.Net\\.WebClient\\)\\.DownloadString\\(|.*system\\.net\\.webclient\\)\\.downloadfile\\())'
```



