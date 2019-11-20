| Title                | Whoami Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/](https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/)</li><li>[https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/](https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-03-001</li><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Whoami Execution
id: e28a5a99-da44-436d-b7a0-2afc20a5f413
status: experimental
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth
date: 2018/08/13
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\whoami.exe'
    selection2:
        OriginalFileName: 'whoami.exe'
    condition: selection or selection2
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment
level: high

```





### splunk
    
```
(Image="*\\\\whoami.exe" OR OriginalFileName="whoami.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Whoami Execution]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Whoami Execution status: experimental \
description: Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators \
references: ['https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/', 'https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/'] \
tags: ['attack.discovery', 'attack.t1033', 'car.2016-03-001'] \
author: Florian Roth \
date:  \
falsepositives: ['Admin activity', 'Scripts and administrative tools used in the monitored environment'] \
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
description = Detects the execution of whoami, which is often used by attackers after exloitation / privilege escalation but rarely used by administrators
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\whoami.exe" OR OriginalFileName="whoami.exe") | stats values(*) AS * by _time | search NOT [| inputlookup Whoami_Execution_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1033,sigma_tag=car.2016-03-001,level=high"
```
