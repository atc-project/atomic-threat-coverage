| Title                | Scheduled Task Creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of scheduled tasks in user session                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Administrative activity</li><li>Software installation</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Scheduled Task Creation
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: experimental
description: Detects the creation of scheduled tasks in user session
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\schtasks.exe'
        CommandLine: '* /create *'
    filter:
        User: NT AUTHORITY\SYSTEM
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053
    - attack.s0111
    - car.2013-08-001
falsepositives:
    - Administrative activity
    - Software installation
level: low

```





### splunk
    
```
((Image="*\\\\schtasks.exe" CommandLine="* /create *") NOT (User="NT AUTHORITY\\\\SYSTEM")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Scheduled Task Creation]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Scheduled Task Creation status: experimental \
description: Detects the creation of scheduled tasks in user session \
references:  \
tags: ['attack.execution', 'attack.persistence', 'attack.privilege_escalation', 'attack.t1053', 'attack.s0111', 'car.2013-08-001'] \
author: Florian Roth \
date:  \
falsepositives: ['Administrative activity', 'Software installation'] \
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
description = Detects the creation of scheduled tasks in user session
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\schtasks.exe" CommandLine="* /create *") NOT (User="NT AUTHORITY\\SYSTEM")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Scheduled_Task_Creation_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1053,sigma_tag=attack.s0111,sigma_tag=car.2013-08-001,level=low"
```
