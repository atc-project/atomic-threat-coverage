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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell called from an Executable Version Mismatch]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell called from an Executable Version Mismatch status: experimental \
description: Detects PowerShell called from an executable by the version mismatch method \
references: ['https://adsecurity.org/?p=2921'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1086'] \
author: Sean Metcalf (source), Florian Roth (rule) \
date:  \
falsepositives: ['Penetration Tests', 'Unknown'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects PowerShell called from an executable by the version mismatch method
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="400" (EngineVersion="2.*" OR EngineVersion="4.*" OR EngineVersion="5.*") HostVersion="3.*") | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_called_from_an_Executable_Version_Mismatch_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
