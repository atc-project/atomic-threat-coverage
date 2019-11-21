| Title                | PowerShell Script Run in AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1082851155481288706](https://twitter.com/JohnLaTwC/status/1082851155481288706)</li><li>[https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03](https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
date: 2019/01/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
    condition: selection
falsepositives:
    - Administrative scripts
level: medium

```





### splunk
    
```
(CommandLine="* /c powershell*\\\\AppData\\\\Local\\\\*" OR CommandLine="* /c powershell*\\\\AppData\\\\Roaming\\\\*")
```



