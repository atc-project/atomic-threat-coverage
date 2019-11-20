| Title                | Backup Catalog Deleted                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects backup catalog deletions                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1107: File Deletion](../Triggers/T1107.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx)</li><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>  |
| Author               | Florian Roth (rule), Tom U. @c_APT_ure (collection) |


## Detection Rules

### Sigma rule

```
title: Backup Catalog Deleted
id: 9703792d-fd9a-456d-a672-ff92efe4806a
status: experimental
description: Detects backup catalog deletions
references:
    - https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth (rule), Tom U. @c_APT_ure (collection)
tags:
    - attack.defense_evasion
    - attack.t1107
logsource:
    product: windows
    service: application
detection:
    selection:
        EventID: 524
        Source: Backup
    condition: selection
falsepositives:
    - Unknown
level: medium


```





### splunk
    
```
(EventID="524" Source="Backup")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Backup Catalog Deleted]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Backup Catalog Deleted status: experimental \
description: Detects backup catalog deletions \
references: ['https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx', 'https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100'] \
tags: ['attack.defense_evasion', 'attack.t1107'] \
author: Florian Roth (rule), Tom U. @c_APT_ure (collection) \
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
description = Detects backup catalog deletions
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="524" Source="Backup") | stats values(*) AS * by _time | search NOT [| inputlookup Backup_Catalog_Deleted_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1107,level=medium"
```
