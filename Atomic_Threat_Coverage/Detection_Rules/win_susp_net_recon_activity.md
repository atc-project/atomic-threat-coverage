| Title                | Reconnaissance Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects activity as "net user administrator /domain" and "net group domain admins /domain"                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069)</li></ul>  |
| Data Needed          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li><li>[T1069: Permission Groups Discovery](../Triggers/T1069.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html](https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html)</li></ul>  |
| Author               | Florian Roth (rule), Jack Croock (method) |
| Other Tags           | <ul><li>attack.s0039</li><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Reconnaissance Activity
id: 968eef52-9cff-4454-8992-1e74b9cbad6c
status: experimental
description: Detects activity as "net user administrator /domain" and "net group domain admins /domain"
references:
    - https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html
author: Florian Roth (rule), Jack Croock (method)
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1069
    - attack.s0039
logsource:
    product: windows
    service: security
    definition: The volume of Event ID 4661 is high on Domain Controllers and therefore "Audit SAM" and "Audit Kernel Object" advanced audit policy settings are not configured in the recommendations for server systems
detection:
    selection:
        - EventID: 4661
          ObjectType: 'SAM_USER'
          ObjectName: 'S-1-5-21-*-500'
          AccessMask: '0x2d'
        - EventID: 4661
          ObjectType: 'SAM_GROUP'
          ObjectName: 'S-1-5-21-*-512'
          AccessMask: '0x2d'
    condition: selection
falsepositives:
    - Administrator activity
    - Penetration tests
level: high

```





### splunk
    
```
(EventID="4661" AccessMask="0x2d" ((ObjectType="SAM_USER" ObjectName="S-1-5-21-*-500") OR (ObjectType="SAM_GROUP" ObjectName="S-1-5-21-*-512")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Reconnaissance Activity]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Reconnaissance Activity status: experimental \
description: Detects activity as "net user administrator /domain" and "net group domain admins /domain" \
references: ['https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html'] \
tags: ['attack.discovery', 'attack.t1087', 'attack.t1069', 'attack.s0039'] \
author: Florian Roth (rule), Jack Croock (method) \
date:  \
falsepositives: ['Administrator activity', 'Penetration tests'] \
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
description = Detects activity as "net user administrator /domain" and "net group domain admins /domain"
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4661" AccessMask="0x2d" ((ObjectType="SAM_USER" ObjectName="S-1-5-21-*-500") OR (ObjectType="SAM_GROUP" ObjectName="S-1-5-21-*-512"))) | stats values(*) AS * by _time | search NOT [| inputlookup Reconnaissance_Activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1087,sigma_tag=attack.t1069,sigma_tag=attack.s0039,level=high"
```
