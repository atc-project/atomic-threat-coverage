| Title                | Rare Scheduled Task Creations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0035_106_task_scheduler_task_registered](../Data_Needed/DN_0035_106_task_scheduler_task_registered.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Scheduled Task Creations
id: b20f6158-9438-41be-83da-a5a16ac90c2b
status: experimental
description: This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count
    function selects tasks with rare names.
tags:
    - attack.persistence
    - attack.t1053
    - attack.s0111
author: Florian Roth
logsource:
    product: windows
    service: taskscheduler
detection:
    selection:
        EventID: 106
    timeframe: 7d
    condition: selection | count() by TaskName < 5 
falsepositives:
    - Software installation
level: low

```





### splunk
    
```
EventID="106" | eventstats count as val by TaskName| search val < 5
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Rare Scheduled Task Creations]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Rare Scheduled Task Creations status: experimental \
description: This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names. \
references:  \
tags: ['attack.persistence', 'attack.t1053', 'attack.s0111'] \
author: Florian Roth \
date:  \
falsepositives: ['Software installation'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = EventID="106" | eventstats count as val by TaskName| search val < 5 | stats values(*) AS * by _time | search NOT [| inputlookup Rare_Scheduled_Task_Creations_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1053,sigma_tag=attack.s0111,level=low"
```
