| Title                | RDP Login from localhost                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | RDP login with localhost source address may be a tunnelled login                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP Login from localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/28
modified: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1076
    - car.2013-07-002
status: experimental
author: Thomas Patzke
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        SourceNetworkAddress:
            - "::1"
            - "127.0.0.1"
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(EventID="4624" LogonType="10" (SourceNetworkAddress="::1" OR SourceNetworkAddress="127.0.0.1"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[RDP Login from localhost]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: RDP Login from localhost status: experimental \
description: RDP login with localhost source address may be a tunnelled login \
references: ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'] \
tags: ['attack.lateral_movement', 'attack.t1076', 'car.2013-07-002'] \
author: Thomas Patzke \
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
description = RDP login with localhost source address may be a tunnelled login
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4624" LogonType="10" (SourceNetworkAddress="::1" OR SourceNetworkAddress="127.0.0.1")) | stats values(*) AS * by _time | search NOT [| inputlookup RDP_Login_from_localhost_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1076,sigma_tag=car.2013-07-002,level=high"
```
