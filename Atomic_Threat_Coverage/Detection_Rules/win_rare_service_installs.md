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
b'# Generated with Sigma2SplunkAlert\n[Rare Service Installs]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Rare Service Installs status: experimental \\\ndescription: Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services \\\nreferences:  \\\ntags: [\'attack.persistence\', \'attack.privilege_escalation\', \'attack.t1050\', \'car.2013-09-005\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Software installation\', \'Software updates\'] \\\nlevel: low\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = EventID="7045" | eventstats count as val by ServiceFileName| search val < 5 | stats values(*) AS * by _time | search NOT [| inputlookup Rare_Service_Installs_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1050,sigma_tag=car.2013-09-005,level=low"\n\n\n'
```
