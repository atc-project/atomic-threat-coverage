| Title                | Addition of SID History to Active Directory Object                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An attacker can use the SID history attribute to gain additional privileges.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1178: SID-History Injection](https://attack.mitre.org/techniques/T1178)</li></ul>  |
| Data Needed          | <ul><li>[DN_0075_4766_attempt_to_add_sid_history_to_an_account_failed](../Data_Needed/DN_0075_4766_attempt_to_add_sid_history_to_an_account_failed.md)</li><li>[DN_0074_4765_sid_history_was_added_to_an_account](../Data_Needed/DN_0074_4765_sid_history_was_added_to_an_account.md)</li><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1178: SID-History Injection](../Triggers/T1178.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Migration of an account into a new domain</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)</li></ul>  |
| Author               | Thomas Patzke, @atc_project (improvements) |


## Detection Rules

### Sigma rule

```
title: Addition of SID History to Active Directory Object
id: 2632954e-db1c-49cb-9936-67d1ef1d17d2
status: stable
description: An attacker can use the SID history attribute to gain additional privileges.
references:
    - https://adsecurity.org/?p=1772
author: Thomas Patzke, @atc_project (improvements)
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1178
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 4765
            - 4766
    selection2:
        EventID: 4738
    selection3:
        SidHistory: 
            - '-'
            - '%%1793'
    condition: selection1 or (selection2 and not selection3)
falsepositives:
    - Migration of an account into a new domain
level: low

```





### splunk
    
```
((EventID="4765" OR EventID="4766") OR (EventID="4738" NOT ((SidHistory="-" OR SidHistory="%%1793"))))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Addition of SID History to Active Directory Object]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Addition of SID History to Active Directory Object status: stable \
description: An attacker can use the SID history attribute to gain additional privileges. \
references: ['https://adsecurity.org/?p=1772'] \
tags: ['attack.persistence', 'attack.privilege_escalation', 'attack.t1178'] \
author: Thomas Patzke, @atc_project (improvements) \
date:  \
falsepositives: ['Migration of an account into a new domain'] \
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
description = An attacker can use the SID history attribute to gain additional privileges.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="4765" OR EventID="4766") OR (EventID="4738" NOT ((SidHistory="-" OR SidHistory="%%1793")))) | stats values(*) AS * by _time | search NOT [| inputlookup Addition_of_SID_History_to_Active_Directory_Object_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.privilege_escalation,sigma_tag=attack.t1178,level=low"
```
