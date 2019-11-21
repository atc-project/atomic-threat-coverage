| Title                | Devtoolslauncher.exe executes specified binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The Devtoolslauncher.exe executes other binary                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Legitimate use of devtoolslauncher.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml)</li><li>[https://twitter.com/_felamos/status/1179811992841797632](https://twitter.com/_felamos/status/1179811992841797632)</li></ul>  |
| Author               | Beyu Denis, oscd.community (rule), @_felamos (idea) |


## Detection Rules

### Sigma rule

```
title: Devtoolslauncher.exe executes specified binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: experimental
description: The Devtoolslauncher.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user

```





### splunk
    
```
(Image="*\\\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```



