| Title                | Admin User Remote Logon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect remote login by Administrator user depending on internal pattern                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2016-04-005](https://car.mitre.org/wiki/CAR-2016-04-005)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2016-04-005</li><li>car.2016-04-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Admin User Remote Logon
id: 0f63e1ef-1eb9-4226-9d54-8927ca08520a
description: Detect remote login by Administrator user depending on internal pattern
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
tags:
    - attack.lateral_movement
    - attack.t1078
    - car.2016-04-005
status: experimental
author: juju4
logsource:
    product: windows
    service: security
    definition: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
detection:
    selection:
        EventID: 4624
        LogonType: 10
        AuthenticationPackageName: Negotiate
        AccountName: 'Admin-*'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low

```





### splunk
    
```
(EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Admin User Remote Logon]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Admin User Remote Logon status: experimental \
description: Detect remote login by Administrator user depending on internal pattern \
references: ['https://car.mitre.org/wiki/CAR-2016-04-005'] \
tags: ['attack.lateral_movement', 'attack.t1078', 'car.2016-04-005'] \
author: juju4 \
date:  \
falsepositives: ['Legitimate administrative activity'] \
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
description = Detect remote login by Administrator user depending on internal pattern
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*") | stats values(*) AS * by _time | search NOT [| inputlookup Admin_User_Remote_Logon_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1078,sigma_tag=car.2016-04-005,level=low"
```
