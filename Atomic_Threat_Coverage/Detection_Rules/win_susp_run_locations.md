| Title        | Suspicious Process Start Locations |
|:-------------------|:------------------|
| Description        | Detects suspicious process run from unusual locations |
| Tags               |   |
| ATT&amp;CK Tactic | ('Defense Evasion', 'TA0005')  |
| ATT&amp;CK Technique | T1036  |
| Dataneeded         | DN_0002_windows_process_creation_with_commandline_4688, DN_0003_windows_sysmon_process_creation_1 |
| Triggering         | T1036 |
| Severity Level     | medium       |
| False Positives    | False positives depend on scripts and administrative tools used in the monitored environment |
| Development Status | experimental      |
| References         | https://car.mitre.org/wiki/CAR-2013-05-002 |
| Author             | juju4      |


## Detection Rules

### Sigma rule

```
action: global
title: Suspicious Process Start Locations
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1036
detection:
    selection:
        CommandLine:
            - "*:\\RECYCLER\\*"
            - "*:\\SystemVolumeInformation\\*"
            - "%windir%\\Tasks\\*"
            - "%systemroot%\\debug\\*"
    condition: selection
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1

```











Graylog

```
b'(EventID:"4688" AND CommandLine:("*\\:\\\\RECYCLER\\*" "*\\:\\\\SystemVolumeInformation\\*" "%windir%\\\\Tasks\\*" "%systemroot%\\\\debug\\*"))\n(EventID:"1" AND CommandLine:("*\\:\\\\RECYCLER\\*" "*\\:\\\\SystemVolumeInformation\\*" "%windir%\\\\Tasks\\*" "%systemroot%\\\\debug\\*"))\n'
```

