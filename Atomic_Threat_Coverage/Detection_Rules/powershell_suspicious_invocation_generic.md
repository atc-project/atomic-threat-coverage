| Title                | Suspicious PowerShell Invocations - Generic                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li><li>Very special / sneaky PowerShell scripts</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Generic
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule)
logsource:
    product: windows
    service: powershell
detection:
    encoded:
        - ' -enc '
        - ' -EncodedCommand '
    hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' - windowstyle hidden '
    noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of them
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
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
((" \\-enc " OR " \\-EncodedCommand ") AND (" \\-w hidden " OR " \\-window hidden " OR " \\- windowstyle hidden ") AND (" \\-noni " OR " \\-noninteractive "))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.* -enc |.* -EncodedCommand )))(?=.*(?:.*(?:.* -w hidden |.* -window hidden |.* - windowstyle hidden )))(?=.*(?:.*(?:.* -noni |.* -noninteractive ))))'
```



