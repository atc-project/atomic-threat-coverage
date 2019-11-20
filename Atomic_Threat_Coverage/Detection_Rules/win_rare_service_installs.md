| Title                | Rare Service Installs                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-09-005</li><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Service Installs
id: 66bfef30-22a5-4fcd-ad44-8d81e60922ae
description: Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious
    services
status: experimental
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
    - car.2013-09-005
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    timeframe: 7d
    condition: selection | count() by ServiceFileName < 5 
falsepositives: 
    - Software installation
    - Software updates
level: low
```





### splunk
    
```
EventID="7045" | eventstats count as val by ServiceFileName| search val < 5
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Rare Service Installs]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Rare Service Installs status: experimental \
description: Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services \
references:  \
tags: ['attack.persistence', 'attack.privilege_escalation', 'attack.t1050', 'car.2013-09-005'] \
author: Florian Roth \
date:  \
falsepositives: ['Software installation', 'Software updates'] \
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
description = Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = EventID="7045" | eventstats count as val by ServiceFileName| search val < 5 | stats values(*) AS * by _time | search NOT [| inputlookup Rare_Service_Installs_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1050,sigma_tag=car.2013-09-005,level=low"
```
