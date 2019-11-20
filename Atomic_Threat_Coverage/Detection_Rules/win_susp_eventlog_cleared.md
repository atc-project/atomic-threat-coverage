| Title                | Eventlog Cleared                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0034_104_log_file_was_cleared](../Data_Needed/DN_0034_104_log_file_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/deviouspolack/status/832535435960209408](https://twitter.com/deviouspolack/status/832535435960209408)</li><li>[https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100](https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Eventlog Cleared
id: d99b79d2-0a6f-4f46-ad8b-260b6e17f982
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
references:
    - https://twitter.com/deviouspolack/status/832535435960209408
    - https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1070
    - car.2016-04-002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
        Source: Microsoft-Windows-Eventlog
    condition: selection
falsepositives:
    - Unknown
level: medium


```





### splunk
    
```
(EventID="104" Source="Microsoft-Windows-Eventlog")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Eventlog Cleared]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Eventlog Cleared status:  \
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution \
references: ['https://twitter.com/deviouspolack/status/832535435960209408', 'https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100'] \
tags: ['attack.defense_evasion', 'attack.t1070', 'car.2016-04-002'] \
author: Florian Roth \
date:  \
falsepositives: ['Unknown'] \
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
description = One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="104" Source="Microsoft-Windows-Eventlog") | stats values(*) AS * by _time | search NOT [| inputlookup Eventlog_Cleared_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1070,sigma_tag=car.2016-04-002,level=medium"
```
