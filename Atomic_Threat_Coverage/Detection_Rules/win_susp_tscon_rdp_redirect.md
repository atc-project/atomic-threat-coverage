| Title                | Suspicious RDP Redirect Using TSCON                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious RDP session redirect using tscon.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html](http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html)</li><li>[https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious RDP Redirect Using TSCON
id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: experimental
description: Detects a suspicious RDP session redirect using tscon.exe
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1076
    - car.2013-07-002
author: Florian Roth
date: 2018/03/17
modified: 2018/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* /dest:rdp-tcp:*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
CommandLine="* /dest:rdp-tcp:*"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious RDP Redirect Using TSCON]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious RDP Redirect Using TSCON status: experimental \
description: Detects a suspicious RDP session redirect using tscon.exe \
references: ['http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html', 'https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6'] \
tags: ['attack.lateral_movement', 'attack.privilege_escalation', 'attack.t1076', 'car.2013-07-002'] \
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
description = Detects a suspicious RDP session redirect using tscon.exe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = CommandLine="* /dest:rdp-tcp:*" | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_RDP_Redirect_Using_TSCON_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1076,sigma_tag=car.2013-07-002,level=high"
```
