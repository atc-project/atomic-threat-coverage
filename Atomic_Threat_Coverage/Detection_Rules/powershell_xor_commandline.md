| Title                | Suspicious XOR Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Sami Ruohonen                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
description: Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.
status: experimental
author: Sami Ruohonen
date: 2018/09/05
tags:
    - attack.execution
    - attack.t1086
detection:
    selection:
        CommandLine:
            - '* -bxor*'
    condition: selection
falsepositives:
    - unknown
level: medium
logsource:
    category: process_creation
    product: windows

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
CommandLine:("* \\-bxor*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*.* -bxor.*)'
```



