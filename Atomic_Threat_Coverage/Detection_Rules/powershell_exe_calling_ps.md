| Title                | PowerShell called from an Executable Version Mismatch                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell called from an executable by the version mismatch method                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0038_400_engine_state_is_changed_from_none_to_available](../Data_Needed/DN_0038_400_engine_state_is_changed_from_none_to_available.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration Tests</li><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| Author               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell called from an Executable Version Mismatch
id: c70e019b-1479-4b65-b0cc-cd0c6093a599
status: experimental
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell-classic
detection:
    selection1:
        EventID: 400
        EngineVersion: 
            - '2.*'
            - '4.*'
            - '5.*'
        HostVersion: '3.*'
    condition: selection1
falsepositives:
    - Penetration Tests
    - Unknown
level: high

```





### splunk
    
```
(EventID="400" (EngineVersion="2.*" OR EngineVersion="4.*" OR EngineVersion="5.*") HostVersion="3.*")
```



