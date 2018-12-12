| Title        | WMI Persistence - Script Event Consumer |
|:-------------------|:------------------|
| Description        | Detects WMI script event consumers |
| Tags               |   |
| ATT&amp;CK Tactic | ('Execution', 'TA0002'), ('Persistence', 'TA0003')  |
| ATT&amp;CK Technique | T1047  |
| Dataneeded         | , , DN_0002_windows_process_creation_with_commandline_4688DN_0001_windows_process_creation_4688, DN_0002_windows_process_creation_with_commandline_4688DN_0001_windows_process_creation_4688 |
| Triggering         | T1047 |
| Severity Level     | high       |
| False Positives    | Legitimate event consumers |
| Development Status | experimental      |
| References         | https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/ |
| Author             | Thomas Patzke      |


## Detection Rules

### Sigma rule

```
---
action: global
title: WMI Persistence - Script Event Consumer
status: experimental
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
detection:
    selection:
        Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
        ParentImage: 'C:\Windows\System32\svchost.exe'
    condition: selection
falsepositives: 
    - Legitimate event consumers
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
b'(EventID:"1" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")\n(EventID:"4688" AND Image:"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" AND ParentImage:"C\\:\\\\Windows\\\\System32\\\\svchost.exe")\n'
```

