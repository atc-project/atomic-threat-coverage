| Title                | Rare Schtasks Creations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Schtasks Creations
id: b0d77106-7bb0-41fe-bd94-d1752164d066
description: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types
    of malicious code
status: experimental
author: Florian Roth
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1053
    - car.2013-08-001
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection (not in the baseline recommendations by Microsoft). We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection:
        EventID: 4698
    timeframe: 7d
    condition: selection | count() by TaskName < 5 
falsepositives: 
    - Software installation
    - Software updates
level: low

```





### splunk
    
```
EventID="4698" | eventstats count as val by TaskName| search val < 5
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Rare Schtasks Creations]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Rare Schtasks Creations status: experimental \\\ndescription: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code \\\nreferences:  \\\ntags: [\'attack.execution\', \'attack.privilege_escalation\', \'attack.persistence\', \'attack.t1053\', \'car.2013-08-001\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Software installation\', \'Software updates\'] \\\nlevel: low\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = EventID="4698" | eventstats count as val by TaskName| search val < 5 | stats values(*) AS * by _time | search NOT [| inputlookup Rare_Schtasks_Creations_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.privilege_escalation,sigma_tag=attack.persistence,sigma_tag=attack.t1053,sigma_tag=car.2013-08-001,level=low"\n\n\n'
```
