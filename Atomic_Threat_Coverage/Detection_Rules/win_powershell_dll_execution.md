| Title                | Detection of PowerShell Execution via DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/p3nt4/PowerShdll/blob/master/README.md](https://github.com/p3nt4/PowerShdll/blob/master/README.md)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Detection of PowerShell Execution via DLL
status: experimental
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.execution
    - attack.t1086
author: Markus Neis
date: 2018/08/25
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\rundll32.exe'
    selection2:
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
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
((Image:("*\\\\rundll32.exe") OR Description:("*Windows\\-Hostprozess \\(Rundll32\\)*")) AND CommandLine:("*Default.GetString*" "*FromBase64String*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*.*\\rundll32\\.exe)|.*(?:.*.*Windows-Hostprozess \\(Rundll32\\).*))))(?=.*(?:.*.*Default\\.GetString.*|.*.*FromBase64String.*)))'
```



