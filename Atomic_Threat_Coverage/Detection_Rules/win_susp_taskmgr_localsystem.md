| Title                | Taskmgr as LOCAL_SYSTEM                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\taskmgr.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```



