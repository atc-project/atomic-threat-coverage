| Title                | Processes created by MMC                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Processes started by MMC could be a sign of lateral movement using MMC application COM object                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1175: Distributed Component Object Model](https://attack.mitre.org/techniques/T1175)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1175: Distributed Component Object Model](../Triggers/T1175.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)</li></ul>                                                          |
| Author               |                                                                                                                                                 |


## Detection Rules

### Sigma rule

```
title: Processes created by MMC
status: experimental
description: Processes started by MMC could be a sign of lateral movement using MMC application COM object
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
tags:
    - attack.lateral_movement
    - attack.t1175
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
        Image: '*\cmd.exe'
    exclusion:
        CommandLine: '*\RunCmd.cmd'
    condition: selection and not exclusion
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((ParentImage:"*\\\\mmc.exe" AND Image:"*\\\\cmd.exe") AND NOT (CommandLine:"*\\\\RunCmd.cmd"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\mmc\\.exe)(?=.*.*\\cmd\\.exe)))(?=.*(?!.*(?:.*(?=.*.*\\RunCmd\\.cmd)))))'
```



