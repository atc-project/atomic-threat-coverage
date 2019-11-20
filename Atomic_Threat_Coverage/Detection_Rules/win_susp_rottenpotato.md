| Title                | RottenPotato Like Attack Pattern                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1171: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1171: LLMNR/NBT-NS Poisoning and Relay](../Triggers/T1171.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1195284233729777665](https://twitter.com/SBousseaden/status/1195284233729777665)</li></ul>  |
| Author               | @SBousseaden, Florian Roth |


## Detection Rules

### Sigma rule

```
title: RottenPotato Like Attack Pattern
id: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
status: experimental
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
references:
    - https://twitter.com/SBousseaden/status/1195284233729777665
author: "@SBousseaden, Florian Roth"
date: 2019/11/15
tags:
    - attack.privilege_escalation
    - attack.credential_access
    - attack.t1171
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS_LOGON'
        WorkstationName: '-'
        SourceNetworkAddress: '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(EventID="4624" LogonType="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[RottenPotato Like Attack Pattern]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: RottenPotato Like Attack Pattern status: experimental \
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like \
references: ['https://twitter.com/SBousseaden/status/1195284233729777665'] \
tags: ['attack.privilege_escalation', 'attack.credential_access', 'attack.t1171'] \
author: @SBousseaden, Florian Roth \
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
description = Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4624" LogonType="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1") | stats values(*) AS * by _time | search NOT [| inputlookup RottenPotato_Like_Attack_Pattern_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.credential_access,sigma_tag=attack.t1171,level=high"
```
