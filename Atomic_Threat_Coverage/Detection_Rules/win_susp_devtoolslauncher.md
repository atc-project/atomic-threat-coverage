| Title                | Devtoolslauncher.exe executes specified binary                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The Devtoolslauncher.exe executes other binary                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Legitimate use of devtoolslauncher.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml)</li><li>[https://twitter.com/_felamos/status/1179811992841797632](https://twitter.com/_felamos/status/1179811992841797632)</li></ul>  |
| Author               | Beyu Denis, oscd.community (rule), @_felamos (idea) |


## Detection Rules

### Sigma rule

```
title: Devtoolslauncher.exe executes specified binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: experimental
description: The Devtoolslauncher.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user

```





### splunk
    
```
(Image="*\\\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Devtoolslauncher.exe executes specified binary]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Devtoolslauncher.exe executes specified binary status: experimental \
description: The Devtoolslauncher.exe executes other binary \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml', 'https://twitter.com/_felamos/status/1179811992841797632'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community (rule), @_felamos (idea) \
date:  \
falsepositives: ['Legitimate use of devtoolslauncher.exe by legitimate user'] \
level: critical
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = The Devtoolslauncher.exe executes other binary
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*") | stats values(*) AS * by _time | search NOT [| inputlookup Devtoolslauncher.exe_executes_specified_binary_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=critical"
```
