| Title        | IIS Native-Code Module Command Line Installation |
|:-------------------|:------------------|
| Description        | Detects suspicious IIS native-code module installations via command line |
| Tags               |   |
| ATT&amp;CK Tactic | ('Persistence', 'TA0003')  |
| ATT&amp;CK Technique | T1100  |
| Dataneeded         | DN_0003_windows_sysmon_process_creation_1, DN_0002_windows_process_creation_with_commandline_4688 |
| Triggering         | T1100: No atomics trigger for this technique |
| Severity Level     | medium       |
| False Positives    | Unknown as it may vary from organisation to arganisation how admins use to install IIS modules |
| Development Status | experimental      |
| References         | https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/ |
| Author             | Florian Roth      |


## Detection Rules

### Sigma rule

```
---
action: global
title: IIS Native-Code Module Command Line Installation
description: Detects suspicious IIS native-code module installations via command line
status: experimental
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
author: Florian Roth
tags:
    - attack.persistence
    - attack.t1100
detection:
    selection:
        CommandLine: 
            - '*\APPCMD.EXE install module /name:*'
    condition: selection
falsepositives: 
    - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium
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
b'(EventID:"1" AND CommandLine:("*\\\\APPCMD.EXE install module \\/name\\:*"))\n(EventID:"4688" AND CommandLine:("*\\\\APPCMD.EXE install module \\/name\\:*"))\n'
```

