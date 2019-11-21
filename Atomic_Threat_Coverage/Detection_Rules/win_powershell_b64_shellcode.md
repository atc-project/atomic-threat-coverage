| Title                | PowerShell Base64 Encoded Shellcode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Base64 encoded Shellcode                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Base64 Encoded Shellcode
id: 2d117e49-e626-4c7c-bd1f-c3c0147774c8
description: Detects Base64 encoded Shellcode
status: experimental
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: Florian Roth
date: 2018/11/17
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*AAAAYInlM*'
    selection2:
        CommandLine:
            - '*OiCAAAAYInlM*'
            - '*OiJAAAAYInlM*'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: critical

```





### splunk
    
```
(CommandLine="*AAAAYInlM*" (CommandLine="*OiCAAAAYInlM*" OR CommandLine="*OiJAAAAYInlM*"))
```



