| Title                | Net.exe Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of Net.exe, whether suspicious or benign.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)</li></ul>                                                          |
| Author               | Michael Haag, Mark Woan (improvements)                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0039</li><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Net.exe Execution
status: experimental
description: Detects execution of Net.exe, whether suspicious or benign.
references:
    - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
author: Michael Haag, Mark Woan (improvements)
tags:
    - attack.s0039
    - attack.lateral_movement
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\net.exe'
            - '*\net1.exe'
        CommandLine:
            - '* group*'
            - '* localgroup*'
            - '* user*'
            - '* view*'
            - '* share'
            - '* accounts*'
            - '* use*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.
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
(Image:("*\\\\net.exe" "*\\\\net1.exe") AND CommandLine:("* group*" "* localgroup*" "* user*" "* view*" "* share" "* accounts*" "* use*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*(?:.*.* group.*|.*.* localgroup.*|.*.* user.*|.*.* view.*|.*.* share|.*.* accounts.*|.*.* use.*)))'
```



