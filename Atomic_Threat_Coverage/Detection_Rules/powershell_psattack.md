| Title                | PowerShell PSAttack                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of PSAttack PowerShell hack tool                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Pentesters</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| Author               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell PSAttack
id: b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
status: experimental
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    selection:
        EventID: 4103
    keyword: 
        - 'PS ATTACK!!!'
    condition: all of them
falsepositives:
    - Pentesters
level: high

```





### splunk
    
```
(EventID="4103" "PS ATTACK!!!")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell PSAttack]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell PSAttack status: experimental \
description: Detects the use of PSAttack PowerShell hack tool \
references: ['https://adsecurity.org/?p=2921'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Sean Metcalf (source), Florian Roth (rule) \
date:  \
falsepositives: ['Pentesters'] \
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
description = Detects the use of PSAttack PowerShell hack tool
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4103" "PS ATTACK!!!") | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_PSAttack_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
