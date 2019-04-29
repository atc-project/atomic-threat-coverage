| Title                | WMI Spawning Windows PowerShell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI spawning PowerShell                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>AppvClient</li><li>CCM</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml](https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml)</li><li>[https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e](https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e)</li></ul>                                                          |
| Author               | Markus Neis / @Karneades                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Spawning Windows PowerShell
status: experimental
description: Detects WMI spawning PowerShell 
references:
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml
    - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
author: Markus Neis / @Karneades
date: 2019/04/03
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wmiprvse.exe'
        Image:
            - '*\powershell.exe'
    condition: selection
falsepositives:
    - AppvClient
    - CCM
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
(ParentImage:("*\\\\wmiprvse.exe") AND Image:("*\\\\powershell.exe"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wmiprvse\\.exe))(?=.*(?:.*.*\\powershell\\.exe)))'
```



