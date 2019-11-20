| Title                | Security Eventlog Cleared                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0038_1102_the_audit_log_was_cleared](../Data_Needed/DN_0038_1102_the_audit_log_was_cleared.md)</li><li>[DN_0050_1102_audit_log_was_cleared](../Data_Needed/DN_0050_1102_audit_log_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)</li><li>System provisioning (system reset before the golden image creation)</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Security Eventlog Cleared
id: f2f01843-e7b8-4f95-a35a-d23584476423
description: Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities
tags:
    - attack.defense_evasion
    - attack.t1070
    - car.2016-04-002
author: Florian Roth
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 517
            - 1102
    condition: selection
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high

```





### splunk
    
```
(EventID="517" OR EventID="1102")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Security Eventlog Cleared]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Security Eventlog Cleared status:  \
description: Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities \
references:  \
tags: ['attack.defense_evasion', 'attack.t1070', 'car.2016-04-002'] \
author: Florian Roth \
date:  \
falsepositives: ['Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)', 'System provisioning (system reset before the golden image creation)'] \
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
description = Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="517" OR EventID="1102") | stats values(*) AS * by _time | search NOT [| inputlookup Security_Eventlog_Cleared_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1070,sigma_tag=car.2016-04-002,level=high"
```
