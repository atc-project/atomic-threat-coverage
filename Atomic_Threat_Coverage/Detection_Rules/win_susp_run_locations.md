| Title                | Suspicious Process Start Locations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process run from unusual locations                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-05-002](https://car.mitre.org/wiki/CAR-2013-05-002)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |
| Other Tags           | <ul><li>car.2013-05-002</li><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Process Start Locations
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*:\RECYCLER\\*'
            - '*:\SystemVolumeInformation\\*'
            - '%windir%\Tasks\\*'
            - '%systemroot%\debug\\*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
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
CommandLine:("*\\:\\\\RECYCLER\\\\*" "*\\:\\\\SystemVolumeInformation\\\\*" "%windir%\\\\Tasks\\\\*" "%systemroot%\\\\debug\\\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*.*:\\RECYCLER\\\\.*|.*.*:\\SystemVolumeInformation\\\\.*|.*%windir%\\Tasks\\\\.*|.*%systemroot%\\debug\\\\.*)'
```



