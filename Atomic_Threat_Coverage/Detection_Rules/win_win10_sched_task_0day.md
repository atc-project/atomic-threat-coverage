| Title                | Windows 10 scheduled task SandboxEscaper 0-day                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Task Scheduler .job import arbitrary DACL write\par                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe](https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe)</li></ul>  |
| Author               | Olaf Hartong |
| Other Tags           | <ul><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows 10 scheduled task SandboxEscaper 0-day
id: 931b6802-d6a6-4267-9ffa-526f57f22aaf
status: experimental
description: Detects Task Scheduler .job import arbitrary DACL write\par
references:
    - https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe
author: Olaf Hartong
date: 2019/05/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: schtasks.exe
        CommandLine: '*/change*/TN*/RU*/RP*'
    condition: selection
falsepositives:
    - Unknown
tags:
    - attack.privilege_escalation
    - attack.execution
    - attack.t1053
    - car.2013-08-001
level: high

```





### splunk
    
```
(Image="schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```



