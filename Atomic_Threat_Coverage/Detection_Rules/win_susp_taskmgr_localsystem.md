| Title                | Taskmgr as LOCAL_SYSTEM                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\taskmgr.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\taskmgr.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Taskmgr as LOCAL_SYSTEM]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Taskmgr as LOCAL_SYSTEM status: experimental \
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM \
references:  \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
date:  \
falsepositives: ['Unkown'] \
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
description = Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (User="NT AUTHORITY\\SYSTEM" Image="*\\taskmgr.exe") | stats values(*) AS * by _time | search NOT [| inputlookup Taskmgr_as_LOCAL_SYSTEM_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
