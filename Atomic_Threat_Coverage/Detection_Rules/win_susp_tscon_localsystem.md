| Title                | Suspicious TSCON Start                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a tscon.exe start as LOCAL SYSTEM                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1219: Remote Access Tools](https://attack.mitre.org/techniques/T1219)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1219: Remote Access Tools](../Triggers/T1219.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)</li><li>[https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious TSCON Start
id: 9847f263-4a81-424f-970c-875dab15b79b
status: experimental
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
author: Florian Roth
date: 2018/03/17
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(User="NT AUTHORITY\\\\SYSTEM" Image="*\\\\tscon.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious TSCON Start]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious TSCON Start status: experimental \
description: Detects a tscon.exe start as LOCAL SYSTEM \
references: ['http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html', 'https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6'] \
tags: ['attack.command_and_control', 'attack.t1219'] \
author: Florian Roth \
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
description = Detects a tscon.exe start as LOCAL SYSTEM
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (User="NT AUTHORITY\\SYSTEM" Image="*\\tscon.exe") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_TSCON_Start_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.command_and_control,sigma_tag=attack.t1219,level=high"
```
