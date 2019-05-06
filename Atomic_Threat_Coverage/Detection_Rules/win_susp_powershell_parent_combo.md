| Title                | Suspicious PowerShell Invocation based on Parent Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell invocations from interpreters or unusual programs                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Microsoft Operations Manager (MOM)</li><li>Other scripts</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/](https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocation based on Parent Process
status: experimental
description: Detects suspicious powershell invocations from interpreters or unusual programs
author: Florian Roth
references:
    - https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
tags:
    - attack.execution
    - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
        Image:
            - '*\powershell.exe'
    falsepositive:
        CurrentDirectory: '*\Health Service State\\*'
    condition: selection and not falsepositive
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
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
((ParentImage:("*\\\\wscript.exe" "*\\\\cscript.exe") AND Image:("*\\\\powershell.exe")) AND NOT (CurrentDirectory:"*\\\\Health Service State\\\\*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*.*\\wscript\\.exe|.*.*\\cscript\\.exe))(?=.*(?:.*.*\\powershell\\.exe))))(?=.*(?!.*(?:.*(?=.*.*\\Health Service State\\\\.*)))))'
```



