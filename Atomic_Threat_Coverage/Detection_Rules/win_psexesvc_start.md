| Title                | PsExec Service Start                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a PsExec service start                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Administrative activity</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0029</li><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PsExec Service Start
description: Detects a PsExec service start
author: Florian Roth
date: 2018/03/13
modified: 2012/12/11
tags:
    - attack.execution
    - attack.t1035
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessCommandLine: C:\Windows\PSEXESVC.exe
    condition: selection
falsepositives:
    - Administrative activity
level: low

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
ProcessCommandLine:"C\\:\\\\Windows\\\\PSEXESVC.exe"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^C:\\Windows\\PSEXESVC\\.exe'
```



