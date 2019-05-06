| Title                | Password Dumper Remote Thread in LSASS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Password Dumper Remote Thread in LSASS 
description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm
status: stable
author: Thomas Patzke
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage: 'C:\Windows\System32\lsass.exe'
        StartModule: null
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
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
(EventID:"8" AND TargetImage:"C\\:\\\\Windows\\\\System32\\\\lsass.exe" AND NOT _exists_:StartModule)
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*C:\\Windows\\System32\\lsass\\.exe)(?=.*(?!StartModule)))'
```



