| Title                | MSHTA Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from MSHTA.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Printer software / driver installations</li><li>HP software</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.trustedsec.com/july-2015/malicious-htas/](https://www.trustedsec.com/july-2015/malicious-htas/)</li></ul>                                                          |
| Author               | Michael Haag                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: MSHTA Spawning Windows Shell
status: experimental
description: Detects a Windows command line executable started from MSHTA.
references:
    - https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mshta.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
falsepositives:
    - Printer software / driver installations
    - HP software
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
(ParentImage:"*\\\\mshta.exe" AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\reg.exe" "*\\\\regsvr32.exe" "*\\\\BITSADMIN*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\mshta\\.exe)(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\reg\\.exe|.*.*\\regsvr32\\.exe|.*.*\\BITSADMIN.*)))'
```



