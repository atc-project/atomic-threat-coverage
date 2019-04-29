| Title                | CMSTP Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects various indicators of Microsoft Connection Manager Profile Installer execution                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1191: CMSTP](../Triggers/T1191.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Legitimate CMSTP use (unlikely in modern enterprise environments)</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/](http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/)</li></ul>                                                          |
| Author               | Nik Seetharaman                                                                                                                                                |
| Other Tags           | <ul><li>attack.g0069</li><li>attack.g0069</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: CMSTP Execution
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1191
    - attack.g0069
author: Nik Seetharaman
references:
    - http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
detection:
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    # Registry Object Add
    selection2:
        EventID: 12
        TargetObject: '*\cmmgr32.exe*'
    # Registry Object Value Set
    selection3:
        EventID: 13
        TargetObject: '*\cmmgr32.exe*'
    # Process Access Call Trace
    selection4:
        EventID: 10
        CallTrace: '*cmlua.dll*'
---
logsource:
    category: process_creation
    product: windows
detection:
    # CMSTP Spawning Child Process
    selection1:
        ParentImage: '*\cmstp.exe'
```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((EventID:"12" AND TargetObject:"*\\\\cmmgr32.exe*") OR (EventID:"13" AND TargetObject:"*\\\\cmmgr32.exe*") OR (EventID:"10" AND CallTrace:"*cmlua.dll*"))\nParentImage:"*\\\\cmstp.exe"
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*12)(?=.*.*\\cmmgr32\\.exe.*))|.*(?:.*(?=.*13)(?=.*.*\\cmmgr32\\.exe.*))|.*(?:.*(?=.*10)(?=.*.*cmlua\\.dll.*))))'\ngrep -P '^.*\\cmstp\\.exe'
```



