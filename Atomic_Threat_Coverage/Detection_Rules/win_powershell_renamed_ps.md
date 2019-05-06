| Title                | Renamed Powershell.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects copying and renaming of powershell.exe before execution (RETEFE malware DOC/macro starting Sept 2018)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>penetration tests, red teaming</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1086/](https://attack.mitre.org/techniques/T1086/)</li><li>[https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/](https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/)</li></ul>                                                          |
| Author               | Tom Ueltschi (@c_APT_ure)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Renamed Powershell.exe
status: experimental
description: Detects copying and renaming of powershell.exe before execution (RETEFE malware DOC/macro starting Sept 2018)
references:
    - https://attack.mitre.org/techniques/T1086/
    - https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/
tags:
    - attack.t1086
    - attack.execution
author: Tom Ueltschi (@c_APT_ure)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: Windows PowerShell
    exclusion_1:
        Image:
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
    exclusion_2:
        Description: Windows PowerShell ISE
    condition: all of selection and not (1 of exclusion_*)
falsepositives:
    - penetration tests, red teaming
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
(Description:"Windows PowerShell" AND NOT ((Image:("*\\\\powershell.exe" "*\\\\powershell_ise.exe") OR Description:"Windows PowerShell ISE")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*Windows PowerShell)(?=.*(?!.*(?:.*(?:.*(?:.*(?:.*.*\\powershell\\.exe|.*.*\\powershell_ise\\.exe)|.*Windows PowerShell ISE))))))'
```



