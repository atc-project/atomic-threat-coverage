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
b'# Generated with Sigma2SplunkAlert\n[RottenPotato Like Attack Pattern]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: RottenPotato Like Attack Pattern status: experimental \\\ndescription: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like \\\nreferences: [\'https://twitter.com/SBousseaden/status/1195284233729777665\'] \\\ntags: [\'attack.privilege_escalation\', \'attack.credential_access\', \'attack.t1171\'] \\\nauthor: @SBousseaden, Florian Roth \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4624" LogonType="3" TargetUserName="ANONYMOUS_LOGON" WorkstationName="-" SourceNetworkAddress="127.0.0.1") | stats values(*) AS * by _time | search NOT [| inputlookup RottenPotato_Like_Attack_Pattern_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.credential_access,sigma_tag=attack.t1171,level=high"\n\n\n'
```
