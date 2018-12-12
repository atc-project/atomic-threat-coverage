| Title        | Hurricane Panda Activity |
|:-------------------|:------------------|
| Description        | Detects Hurricane Panda Activity |
| Tags               | attack.g0009  |
| ATT&amp;CK Tactic | ('Privilege Escalation', 'TA0004')  |
| ATT&amp;CK Technique | T1068  |
| Dataneeded         | DN_0003_windows_sysmon_process_creation_1, DN_0002_windows_process_creation_with_commandline_4688 |
| Triggering         | T1068: No atomics trigger for this technique |
| Severity Level     | high       |
| False Positives    | Unknown |
| Development Status | experimental      |
| References         | https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/ |
| Author             | Florian Roth      |


## Detection Rules

### Sigma rule

```
---
action: global
title: Hurricane Panda Activity
status: experimental
description: Detects Hurricane Panda Activity 
references: 
    - https://www.crowdstrike.com/blog/crowdstrike-discovers-use-64-bit-zero-day-privilege-escalation-exploit-cve-2014-4113-hurricane-panda/
tags:
    - attack.privilege_escalation
    - attack.g0009
    - attack.t1068
author: Florian Roth
date: 2018/02/25
detection:
    selection:
        CommandLine: 
            - '* localgroup administrators admin /add'
            - '*\Win64.exe*'
    condition: selection
falsepositives:
    - Unknown
level: high
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688



```











Graylog

```
b'(EventID:"1" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))\n(EventID:"4688" AND CommandLine:("* localgroup administrators admin \\/add" "*\\\\Win64.exe*"))\n'
```

