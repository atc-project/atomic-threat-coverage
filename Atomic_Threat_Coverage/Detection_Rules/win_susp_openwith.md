| Title                | OpenWith.exe executes specified binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The OpenWith.exe executes other binary                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate use of OpenWith.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml)</li><li>[https://twitter.com/harr0ey/status/991670870384021504](https://twitter.com/harr0ey/status/991670870384021504)</li></ul>  |
| Author               | Beyu Denis, oscd.community (rule), @harr0ey (idea) |


## Detection Rules

### Sigma rule

```
title: OpenWith.exe executes specified binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: experimental
description: The OpenWith.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
    - https://twitter.com/harr0ey/status/991670870384021504
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\OpenWith.exe'
        CommandLine|contains: '/c'
    condition: selection
falsepositives:
    - Legitimate use of OpenWith.exe by legitimate user

```





### splunk
    
```
(Image="*\\\\OpenWith.exe" CommandLine="*/c*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[OpenWith.exe executes specified binary]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: OpenWith.exe executes specified binary status: experimental \
description: The OpenWith.exe executes other binary \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml', 'https://twitter.com/harr0ey/status/991670870384021504'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community (rule), @harr0ey (idea) \
date:  \
falsepositives: ['Legitimate use of OpenWith.exe by legitimate user'] \
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
description = The OpenWith.exe executes other binary
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\OpenWith.exe" CommandLine="*/c*") | stats values(*) AS * by _time | search NOT [| inputlookup OpenWith.exe_executes_specified_binary_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=high"
```
