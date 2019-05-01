| Title                | LockerGoga Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a command that clears the WMI trace log which indicates LockaerGoga ransomware activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://abuse.io/lockergoga.txt](https://abuse.io/lockergoga.txt)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: LockerGoga Ransomware
description: Detects a command that clears the WMI trace log which indicates LockaerGoga ransomware activity
references:
    - https://abuse.io/lockergoga.txt
author: Florian Roth
date: 2019/03/22
tags:
    - attack.execution
    - attack.t1064    
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* cl Microsoft-Windows-WMI-Activity/Trace'
    condition: selection


```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
CommandLine:"* cl Microsoft\\-Windows\\-WMI\\-Activity\\/Trace"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^.* cl Microsoft-Windows-WMI-Activity/Trace'
```



