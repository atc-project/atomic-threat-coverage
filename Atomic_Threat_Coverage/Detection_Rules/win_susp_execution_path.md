| Title                | Execution in Non-Executable Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious exection from an uncommon folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Execution in Non-Executable Folder
status: experimental
description: Detects a suspicious exection from an uncommon folder
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
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
Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\All Users\\\\*" "*\\\\Users\\\\Default\\\\*" "*\\\\Users\\\\Public\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\config\\\\systemprofile\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*.*\\\\$Recycle\\.bin|.*.*\\Users\\All Users\\\\.*|.*.*\\Users\\Default\\\\.*|.*.*\\Users\\Public\\\\.*|.*C:\\Perflogs\\\\.*|.*.*\\config\\systemprofile\\\\.*|.*.*\\Windows\\Fonts\\\\.*|.*.*\\Windows\\IME\\\\.*|.*.*\\Windows\\addins\\\\.*)'
```



