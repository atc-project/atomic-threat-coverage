| Title                | Suspicious Svchost Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious svchost process start                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Svchost Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: experimental
description: Detects a suspicious svchost process start
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2017/08/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\svchost.exe'
    filter:
        ParentImage:
            - '*\services.exe'
            - '*\MsMpEng.exe'
            - '*\Mrt.exe'
            - '*\rpcnet.exe'
    filter_null:
        ParentImage: null
    condition: selection and not filter and not filter_null
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
((Image="*\\\\svchost.exe" NOT ((ParentImage="*\\\\services.exe" OR ParentImage="*\\\\MsMpEng.exe" OR ParentImage="*\\\\Mrt.exe" OR ParentImage="*\\\\rpcnet.exe"))) NOT (NOT ParentImage="*")) | table CommandLine,ParentCommandLine
```



