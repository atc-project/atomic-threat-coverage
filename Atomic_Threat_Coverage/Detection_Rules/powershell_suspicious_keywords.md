| Title                | Suspicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords that could indicate the use of some PowerShell exploitation framework                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Keywords
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: powershell
    definition: 'It is recommanded to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        - System.Reflection.Assembly.Load
    condition: keywords
falsepositives:
    - Penetration tests
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
"System.Reflection.Assembly.Load"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^System\\.Reflection\\.Assembly\\.Load'
```



