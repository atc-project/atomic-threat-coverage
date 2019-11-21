| Title                | PowerShell Downgrade Attack                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0038_400_engine_state_is_changed_from_none_to_available](../Data_Needed/DN_0038_400_engine_state_is_changed_from_none_to_available.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)</li></ul>  |
| Author               | Florian Roth (rule), Lee Holmes (idea) |


## Detection Rules

### Sigma rule

```
title: PowerShell Downgrade Attack
id: 6331d09b-4785-4c13-980f-f96661356249
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
author: Florian Roth (rule), Lee Holmes (idea)
logsource:
    product: windows
    service: powershell-classic
detection:
    selection:
        EventID: 400
        EngineVersion: '2.*'
    filter:
        HostVersion: '2.*' 
    condition: selection and not filter
falsepositives:
    - Penetration Test
    - Unknown
level: medium

```





### splunk
    
```
((EventID="400" EngineVersion="2.*") NOT (HostVersion="2.*"))
```



