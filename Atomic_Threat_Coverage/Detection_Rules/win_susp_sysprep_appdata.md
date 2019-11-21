| Title                | Sysprep on AppData Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets](https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets)</li><li>[https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b](https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Sysprep on AppData Folder
id: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
status: experimental
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
tags:
    - attack.execution
author: Florian Roth
date: 2018/06/22
modified: 2018/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\sysprep.exe *\AppData\\*'
            - sysprep.exe *\AppData\\*
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(CommandLine="*\\\\sysprep.exe *\\\\AppData\\\\*" OR CommandLine="sysprep.exe *\\\\AppData\\\\*")
```



