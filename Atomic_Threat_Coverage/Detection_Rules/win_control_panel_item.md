| Title                | Control Panel Items                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of a control panel item (.cpl) outside of the System32 folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1196: Control Panel Items](../Triggers/T1196.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Kyaw Min Thein |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the use of a control panel item (.cpl) outside of the System32 folder
reference:
    - https://attack.mitre.org/techniques/T1196/
tags:
    - attack.execution
    - attack.t1196
    - attack.defense_evasion
author: Kyaw Min Thein
date: 2019/08/27
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    condition: selection and not filter
falsepositives:
    - Unknown

```





### splunk
    
```
(CommandLine="*.cpl" NOT ((CommandLine="*\\\\System32\\\\*" OR CommandLine="*%System%*")))
```



