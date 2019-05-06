| Title                | QuarksPwDump Dump File                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a dump file written by QuarksPwDump password dumper                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: QuarksPwDump Dump File
status: experimental
description: Detects a dump file written by QuarksPwDump password dumper
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm
author: Florian Roth
date: 2018/02/10
tags:
  - attack.credential_access
  - attack.t1003
level: critical
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        # Sysmon: File Creation (ID 11)
        EventID: 11
        TargetFilename: '*\AppData\Local\Temp\SAM-*.dmp*'
    condition: selection
falsepositives:
    - Unknown


```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"11" AND TargetFilename:"*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\\AppData\\Local\\Temp\\SAM-.*\\.dmp.*))'
```



