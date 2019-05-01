| Title                | PowerShell Download from URL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Powershell process that contains download commands in its command line string                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell Download from URL
status: experimental
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth
tags:
    - attack.t1086
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
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
(Image:"*\\\\powershell.exe" AND CommandLine:("*new\\-object system.net.webclient\\).downloadstring\\(*" "*new\\-object system.net.webclient\\).downloadfile\\(*" "*new\\-object net.webclient\\).downloadstring\\(*" "*new\\-object net.webclient\\).downloadfile\\(*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*(?:.*.*new-object system\\.net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object system\\.net\\.webclient\\)\\.downloadfile\\(.*|.*.*new-object net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object net\\.webclient\\)\\.downloadfile\\(.*)))'
```



