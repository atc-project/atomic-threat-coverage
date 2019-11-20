| Title                | Enabled User Right in AD to Control User Objects                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0066_4704_user_right_was_assigned](../Data_Needed/DN_0066_4704_user_right_was_assigned.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Enabled User Right in AD to Control User Objects
id: 311b6ce2-7890-4383-a8c2-663a9f6b43cd
description: Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.
tags:
    - attack.privilege_escalation
    - attack.t1078
references:
    - https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
author: '@neu5ron'
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Policy Change > Audit Authorization Policy Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4704
    keywords:
        Message:
            - '*SeEnableDelegationPrivilege*'
    condition: all of them
falsepositives: 
    - Unknown
level: high

```





### splunk
    
```
(EventID="4704" (Message="*SeEnableDelegationPrivilege*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Enabled User Right in AD to Control User Objects]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Enabled User Right in AD to Control User Objects status:  \
description: Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects. \
references: ['https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/'] \
tags: ['attack.privilege_escalation', 'attack.t1078'] \
author: @neu5ron \
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
description = Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4704" (Message="*SeEnableDelegationPrivilege*")) | stats values(*) AS * by _time | search NOT [| inputlookup Enabled_User_Right_in_AD_to_Control_User_Objects_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1078,level=high"
```
