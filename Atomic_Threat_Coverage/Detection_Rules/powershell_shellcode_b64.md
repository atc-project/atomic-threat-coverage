| Title                | PowerShell ShellCode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Base64 encoded Shellcode                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>                                                          |
| Author               | David Ledbetter (shellcode), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell ShellCode
status: experimental
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
tags:
    - attack.privilege_escalation
    - attack.execution
    - attack.t1055
    - attack.t1086
author: David Ledbetter (shellcode), Florian Roth (rule)
date: 2018/11/17
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1: 
        - '*AAAAYInlM*'
    keyword2: 
        - '*OiCAAAAYInlM*'
        - '*OiJAAAAYInlM*'
    condition: selection and keyword1 and keyword2
falsepositives:
    - Unknown
level: critical

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((EventID:"4104" AND "*AAAAYInlM*") AND ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4104)(?=.*.*AAAAYInlM.*)))(?=.*(?:.*(?:.*.*OiCAAAAYInlM.*|.*.*OiJAAAAYInlM.*))))'
```



