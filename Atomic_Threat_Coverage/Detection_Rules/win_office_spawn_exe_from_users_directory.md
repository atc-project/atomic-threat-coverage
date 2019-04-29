| Title                | MS Office Product Spawning Exe in User Dir                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[{'sha256': '23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c'}]({'sha256': '23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c'})</li><li>[https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign](https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign)</li></ul>                                                          |
| Author               | Jason Lynch                                                                                                                                                |
| Other Tags           | <ul><li>FIN7</li><li>FIN7</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MS Office Product Spawning Exe in User Dir 
status: experimental
description: Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio
references:
    - sha256: 23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c
    - https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign 
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1202
    - FIN7
author: Jason Lynch 
date: 2019/04/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - 'C:\users\*.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
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
(ParentImage:("*\\\\WINWORD.EXE" "*\\\\EXCEL.EXE" "*\\\\POWERPNT.exe" "*\\\\MSPUB.exe" "*\\\\VISIO.exe" "*\\\\OUTLOOK.EXE") AND Image:("C\\:\\\\users\\*.exe"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\WINWORD\\.EXE|.*.*\\EXCEL\\.EXE|.*.*\\POWERPNT\\.exe|.*.*\\MSPUB\\.exe|.*.*\\VISIO\\.exe|.*.*\\OUTLOOK\\.EXE))(?=.*(?:.*C:\\users\\.*\\.exe)))'
```



