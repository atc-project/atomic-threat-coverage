| Title                | CACTUSTORCH Remote Thread Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote thread creation from CACTUSTORCH as described in references.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1090588499517079552](https://twitter.com/SBousseaden/status/1090588499517079552)</li><li>[https://github.com/mdsecactivebreach/CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH)</li></ul>                                                          |
| Author               | @SBousseaden (detection), Thomas Patzke (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: CACTUSTORCH Remote Thread Creation
description: Detects remote thread creation from CACTUSTORCH as described in references.
references:
    - https://twitter.com/SBousseaden/status/1090588499517079552
    - https://github.com/mdsecactivebreach/CACTUSTORCH
status: experimental
author: "@SBousseaden (detection), Thomas Patzke (rule)"
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage:
            - '*\System32\cscript.exe'
            - '*\System32\wscript.exe'
            - '*\System32\mshta.exe'
            - '*\winword.exe'
            - '*\excel.exe'
        TargetImage: '*\SysWOW64\\*'
        StartModule: null
    condition: selection
tags:
    - attack.execution
    - attack.t1055
    - attack.t1064
falsepositives:
    - unknown
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
(EventID:"8" AND SourceImage:("*\\\\System32\\\\cscript.exe" "*\\\\System32\\\\wscript.exe" "*\\\\System32\\\\mshta.exe" "*\\\\winword.exe" "*\\\\excel.exe") AND TargetImage:"*\\\\SysWOW64\\\\*" AND NOT _exists_:StartModule)
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*(?:.*.*\\System32\\cscript\\.exe|.*.*\\System32\\wscript\\.exe|.*.*\\System32\\mshta\\.exe|.*.*\\winword\\.exe|.*.*\\excel\\.exe))(?=.*.*\\SysWOW64\\\\.*)(?=.*(?!StartModule)))'
```



