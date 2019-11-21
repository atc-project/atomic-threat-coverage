| Title                | Ransomware Deletes Volume Shadow Copies                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects commands that delete all local volume shadow copies as used by different Ransomware families                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Adminsitrative scripts - e.g. to prepare image for golden image creation</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/](https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/)</li><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Ransomware Deletes Volume Shadow Copies
id: 4eebe114-4b24-4a9d-9a6c-c7bd7c8eaa61
status: experimental
description: Detects commands that delete all local volume shadow copies as used by different Ransomware families
references:
    - https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth
date: 2019/06/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*vssadmin delete shadows*'
            - '*wmic SHADOWCOPY DELETE*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Adminsitrative scripts - e.g. to prepare image for golden image creation
level: critical

```





### splunk
    
```
(CommandLine="*vssadmin delete shadows*" OR CommandLine="*wmic SHADOWCOPY DELETE*") | table CommandLine,ParentCommandLine
```



