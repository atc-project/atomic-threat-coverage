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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell Downgrade Attack]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell Downgrade Attack status: experimental \
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0 \
references: ['http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1086'] \
author: Florian Roth (rule), Lee Holmes (idea) \
date:  \
falsepositives: ['Penetration Test', 'Unknown'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="400" EngineVersion="2.*") NOT (HostVersion="2.*")) | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_Downgrade_Attack_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1086,level=medium"
```
