| Title                | Remote Task Creation via ATSVC named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote task creation via at.exe or API interacting with ATSVC namedpipe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>pentesting</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html](https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html)</li></ul>  |
| Author               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-05-004</li><li>car.2013-05-004</li><li>car.2015-04-001</li><li>car.2015-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Remote Task Creation via ATSVC named pipe
id: f6de6525-4509-495a-8a82-1f8b0ed73a00
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1053
    - car.2013-05-004
    - car.2015-04-001
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: atsvc
        Accesses: '*WriteData*'
    condition: selection
falsepositives: 
    - pentesting
level: medium

```





### splunk
    
```
(EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="atsvc" Accesses="*WriteData*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Remote Task Creation via ATSVC named pipe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Remote Task Creation via ATSVC named pipe status:  \
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe \
references: ['https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html'] \
tags: ['attack.lateral_movement', 'attack.persistence', 'attack.t1053', 'car.2013-05-004', 'car.2015-04-001'] \
author: Samir Bousseaden \
date:  \
falsepositives: ['pentesting'] \
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
description = Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="5145" ShareName="\\*\\IPC$" RelativeTargetName="atsvc" Accesses="*WriteData*") | stats values(*) AS * by _time | search NOT [| inputlookup Remote_Task_Creation_via_ATSVC_named_pipe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.persistence,sigma_tag=attack.t1053,sigma_tag=car.2013-05-004,sigma_tag=car.2015-04-001,level=medium"
```
