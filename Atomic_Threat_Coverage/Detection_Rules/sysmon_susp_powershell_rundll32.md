| Title                | PowerShell Rundll32 Remote Thread Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell remote thread creation in Rundll32.exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unkown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html](https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell Rundll32 Remote Thread Creation
status: experimental
description: Detects PowerShell remote thread creation in Rundll32.exe 
author: Florian Roth
references:
    - https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html
date: 2018/06/25
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage: '*\powershell.exe'
        TargetImage: '*\rundll32.exe'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
    - attack.t1086
falsepositives:
    - Unkown
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
(EventID:"8" AND SourceImage:"*\\\\powershell.exe" AND TargetImage:"*\\\\rundll32.exe")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*.*\\powershell\\.exe)(?=.*.*\\rundll32\\.exe))'
```



