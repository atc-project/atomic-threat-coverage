| Title                | Suspicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords that could indicate the use of some PowerShell exploitation framework                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Keywords
id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        Message:
            - "*[System.Reflection.Assembly]::Load*"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### splunk
    
```
(Message="*[System.Reflection.Assembly]::Load*")
```



