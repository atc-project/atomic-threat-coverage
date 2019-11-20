| Title                | Windows 10 scheduled task SandboxEscaper 0-day                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Task Scheduler .job import arbitrary DACL write\par                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe](https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe)</li></ul>  |
| Author               | Olaf Hartong |
| Other Tags           | <ul><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows 10 scheduled task SandboxEscaper 0-day
id: 931b6802-d6a6-4267-9ffa-526f57f22aaf
status: experimental
description: Detects Task Scheduler .job import arbitrary DACL write\par
references:
    - https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe
author: Olaf Hartong
date: 2019/05/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: schtasks.exe
        CommandLine: '*/change*/TN*/RU*/RP*'
    condition: selection
falsepositives:
    - Unknown
tags:
    - attack.privilege_escalation
    - attack.execution
    - attack.t1053
    - car.2013-08-001
level: high

```





### splunk
    
```
(Image="schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Windows 10 scheduled task SandboxEscaper 0-day]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Windows 10 scheduled task SandboxEscaper 0-day status: experimental \
description: Detects Task Scheduler .job import arbitrary DACL write\par \
references: ['https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe'] \
tags: ['attack.privilege_escalation', 'attack.execution', 'attack.t1053', 'car.2013-08-001'] \
author: Olaf Hartong \
date:  \
falsepositives: ['Unknown'] \
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
description = Detects Task Scheduler .job import arbitrary DACL write\par
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*") | stats values(*) AS * by _time | search NOT [| inputlookup Windows_10_scheduled_task_SandboxEscaper_0-day_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.execution,sigma_tag=attack.t1053,sigma_tag=car.2013-08-001,level=high"
```
