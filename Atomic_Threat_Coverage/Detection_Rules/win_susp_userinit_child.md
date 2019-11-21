| Title                | Suspicious Userinit Child Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious child process of userinit                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1139811587760562176](https://twitter.com/SBousseaden/status/1139811587760562176)</li></ul>  |
| Author               | Florian Roth (rule), Samir Bousseaden (idea) |


## Detection Rules

### Sigma rule

```
title: Suspicious Userinit Child Process
id: b655a06a-31c0-477a-95c2-3726b83d649d
status: experimental
description: Detects a suspicious child process of userinit
references:
    - https://twitter.com/SBousseaden/status/1139811587760562176
author: Florian Roth (rule), Samir Bousseaden (idea)
date: 2019/06/17
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\userinit.exe'
    filter1:
        CommandLine: '*\\netlogon\\*'
    filter2:
        Image: '*\explorer.exe'
    condition: selection and not filter1 and not filter2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: medium

```





### splunk
    
```
((ParentImage="*\\\\userinit.exe" NOT (CommandLine="*\\\\netlogon\\\\*")) NOT (Image="*\\\\explorer.exe")) | table CommandLine,ParentCommandLine
```



