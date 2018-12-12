| Title        | Reconnaissance Activity with Net Command |
|:-------------------|:------------------|
| Description        | Detects a set of commands often used in recon stages by different attack groups |
| Tags               |   |
| ATT&amp;CK Tactic | ('Discovery', 'TA0007')  |
| ATT&amp;CK Technique | T1073, T1012  |
| Dataneeded         | DN_0003_windows_sysmon_process_creation_1, DN_0002_windows_process_creation_with_commandline_4688 |
| Triggering         | T1073: No atomics trigger for this technique, T1012 |
| Severity Level     | medium       |
| False Positives    | False positives depend on scripts and administrative tools used in the monitored environment |
| Development Status | experimental      |
| References         | https://twitter.com/haroonmeer/status/939099379834658817, https://twitter.com/c_APT_ure/status/939475433711722497, https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html |
| Author             | Florian Roth, Markus Neis      |


## Detection Rules

### Sigma rule

```
---
action: global
title: Reconnaissance Activity with Net Command
status: experimental
description: 'Detects a set of commands often used in recon stages by different attack groups' 
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author:  Florian Roth, Markus Neis
date: 2018/08/22
tags:
    - attack.discovery
    - attack.t1073
    - attack.t1012 
detection:
    selection:
        CommandLine: 
            - 'tasklist'
            - 'net time'
            - 'systeminfo'
            - 'whoami'
            - 'nbtstat'
            - 'net start'
            - '*\net1 start'
            - 'qprocess'
            - 'nslookup'
            - 'hostname.exe'
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain' 
            - '*\net1 user net localgroup administrators' 
            - 'netstat -an'
    timeframe: 15s 
    condition: selection | count() > 4
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
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
b''
```

