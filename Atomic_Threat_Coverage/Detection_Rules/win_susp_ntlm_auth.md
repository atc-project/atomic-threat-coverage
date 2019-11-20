| Title                | NTLM Logon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects logons using NTLM, which could be caused by a legacy source or attackers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0082_8002_ntlm_server_blocked_audit](../Data_Needed/DN_0082_8002_ntlm_server_blocked_audit.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legacy hosts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1004895028995477505](https://twitter.com/JohnLaTwC/status/1004895028995477505)</li><li>[https://goo.gl/PsqrhT](https://goo.gl/PsqrhT)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: NTLM Logon
id: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b
status: experimental
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth
date: 2018/06/08
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: ntlm
    definition: Reqiures events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        CallingProcessName: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```





### splunk
    
```
(EventID="8002" CallingProcessName="*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[NTLM Logon]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: NTLM Logon status: experimental \
description: Detects logons using NTLM, which could be caused by a legacy source or attackers \
references: ['https://twitter.com/JohnLaTwC/status/1004895028995477505', 'https://goo.gl/PsqrhT'] \
tags: ['attack.lateral_movement', 'attack.t1075'] \
author: Florian Roth \
date:  \
falsepositives: ['Legacy hosts'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects logons using NTLM, which could be caused by a legacy source or attackers
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="8002" CallingProcessName="*") | stats values(*) AS * by _time | search NOT [| inputlookup NTLM_Logon_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1075,level=low"
```
