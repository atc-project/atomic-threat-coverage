| Title                | Suspicious Calculator Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/ItsReallyNick/status/1094080242686312448](https://twitter.com/ItsReallyNick/status/1094080242686312448)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Calculator Usage
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
        - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
        category: process_creation
        product: windows
detection:
        selection1:
                CommandLine: '*\calc.exe *'
        selection2:
                Image: '*\calc.exe'
        filter2:
                Image: '*\Windows\Sys*'
        condition: selection1 or ( selection2 and not filter2 )
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
(CommandLine:"*\\\\calc.exe *" OR (Image:"*\\\\calc.exe" AND NOT (Image:"*\\\\Windows\\\\Sys*")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\calc\\.exe .*|.*(?:.*(?=.*.*\\calc\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Windows\\Sys.*)))))))'
```



