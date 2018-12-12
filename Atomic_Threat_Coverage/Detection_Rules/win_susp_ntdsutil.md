| Title        | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) |
|:-------------------|:------------------|
| Description        | Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT) |
| Tags               |   |
| ATT&amp;CK Tactic | ('Credential Access', 'TA0006')  |
| ATT&amp;CK Technique | T1003  |
| Dataneeded         | DN_0003_windows_sysmon_process_creation_1, DN_0002_windows_process_creation_with_commandline_4688 |
| Triggering         | T1003 |
| Severity Level     | high       |
| False Positives    | NTDS maintenance |
| Development Status | experimental      |
| References         | https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm |
| Author             | Thomas Patzke      |


## Detection Rules

### Sigma rule

```
---
action: global
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
status: experimental
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
tags:
    - attack.credential_access
    - attack.t1003
detection:
    selection:
        CommandLine: '*\ntdsutil.exe *'
    condition: selection
falsepositives: 
    - NTDS maintenance
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
b'(EventID:"1" AND CommandLine:"*\\\\ntdsutil.exe *")\n(EventID:"4688" AND CommandLine:"*\\\\ntdsutil.exe *")\n'
```

