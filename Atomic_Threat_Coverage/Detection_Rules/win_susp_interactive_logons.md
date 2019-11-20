| Title                | Interactive Logon to Server Systems                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects interactive console logons to                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0041_529_logon_failure](../Data_Needed/DN_0041_529_logon_failure.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0040_528_user_successfully_logged_on_to_a_computer](../Data_Needed/DN_0040_528_user_successfully_logged_on_to_a_computer.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative activity via KVM or ILO board</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Interactive Logon to Server Systems
id: 3ff152b2-1388-4984-9cd9-a323323fdadf
description: Detects interactive console logons to
author: Florian Roth
tags:
    - attack.lateral_movement
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 529
            - 4624
            - 4625
        LogonType: 2
        ComputerName:
            - '%ServerSystems%'
            - '%DomainControllers%'
    filter:
        LogonProcessName: Advapi
        ComputerName: '%Workstations%'
    condition: selection and not filter
falsepositives:
    - Administrative activity via KVM or ILO board
level: medium



```





### splunk
    
```
(((EventID="528" OR EventID="529" OR EventID="4624" OR EventID="4625") LogonType="2" (ComputerName="%ServerSystems%" OR ComputerName="%DomainControllers%")) NOT (LogonProcessName="Advapi" ComputerName="%Workstations%"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Interactive Logon to Server Systems]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Interactive Logon to Server Systems status:  \
description: Detects interactive console logons to \
references:  \
tags: ['attack.lateral_movement', 'attack.t1078'] \
author: Florian Roth \
date:  \
falsepositives: ['Administrative activity via KVM or ILO board'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects interactive console logons to
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((EventID="528" OR EventID="529" OR EventID="4624" OR EventID="4625") LogonType="2" (ComputerName="%ServerSystems%" OR ComputerName="%DomainControllers%")) NOT (LogonProcessName="Advapi" ComputerName="%Workstations%")) | stats values(*) AS * by _time | search NOT [| inputlookup Interactive_Logon_to_Server_Systems_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1078,level=medium"
```
