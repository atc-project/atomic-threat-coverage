| Title                | User Added to Local Administrators                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0069_4732_member_was_added_to_security_enabled_local_group](../Data_Needed/DN_0069_4732_member_was_added_to_security_enabled_local_group.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | stable |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: User Added to Local Administrators
id: c265cf08-3f99-46c1-8d59-328247057d57
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation
    activity
status: stable
author: Florian Roth
tags:
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
    selection_group1:
        GroupName: 'Administrators'
    selection_group2:
        GroupSid: 'S-1-5-32-544'
    filter:
        SubjectUserName: '*$'
    condition: selection and (1 of selection_group*) and not filter
falsepositives:
    - Legitimate administrative activity
level: medium

```





### splunk
    
```
((EventID="4732" (GroupName="Administrators" OR GroupSid="S-1-5-32-544")) NOT (SubjectUserName="*$"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[User Added to Local Administrators]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: User Added to Local Administrators status: stable \
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity \
references:  \
tags: ['attack.privilege_escalation', 'attack.t1078'] \
author: Florian Roth \
date:  \
falsepositives: ['Legitimate administrative activity'] \
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
description = This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="4732" (GroupName="Administrators" OR GroupSid="S-1-5-32-544")) NOT (SubjectUserName="*$")) | stats values(*) AS * by _time | search NOT [| inputlookup User_Added_to_Local_Administrators_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1078,level=medium"
```
