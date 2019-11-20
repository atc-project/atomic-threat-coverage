| Title                | RDP over Reverse SSH Tunnel WFP                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| Data Needed          | <ul><li>[DN_0087_5156_windows_filtering_platform_has_permitted_connection](../Data_Needed/DN_0087_5156_windows_filtering_platform_has_permitted_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1096148422984384514](https://twitter.com/SBousseaden/status/1096148422984384514)</li></ul>  |
| Author               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP over Reverse SSH Tunnel WFP
id: 5bed80b6-b3e8-428e-a3ae-d3c757589e41
status: experimental
description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
author: Samir Bousseaden
date: 2019/02/16
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1076
    - car.2013-07-002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
    sourceRDP:
        SourcePort: 3389
        DestinationAddress:
            - '127.*'
            - '::1'
    destinationRDP:
        DestinationPort: 3389
        SourceAddress:
            - '127.*'
            - '::1'
    condition: selection and ( sourceRDP or destinationRDP )
falsepositives:
    - unknown
level: high

```





### splunk
    
```
(EventID="5156" ((SourcePort="3389" (DestinationAddress="127.*" OR DestinationAddress="::1")) OR (DestinationPort="3389" (SourceAddress="127.*" OR SourceAddress="::1"))))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[RDP over Reverse SSH Tunnel WFP]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: RDP over Reverse SSH Tunnel WFP status: experimental \
description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389 \
references: ['https://twitter.com/SBousseaden/status/1096148422984384514'] \
tags: ['attack.defense_evasion', 'attack.command_and_control', 'attack.t1076', 'car.2013-07-002'] \
author: Samir Bousseaden \
date:  \
falsepositives: ['unknown'] \
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
description = Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="5156" ((SourcePort="3389" (DestinationAddress="127.*" OR DestinationAddress="::1")) OR (DestinationPort="3389" (SourceAddress="127.*" OR SourceAddress="::1")))) | stats values(*) AS * by _time | search NOT [| inputlookup RDP_over_Reverse_SSH_Tunnel_WFP_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.command_and_control,sigma_tag=attack.t1076,sigma_tag=car.2013-07-002,level=high"
```
