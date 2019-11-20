| Title                | AD Privileged Users or Groups Reconnaissance                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>if source account name is not an admin then its super suspicious</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html](https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: AD Privileged Users or Groups Reconnaissance
id: 35ba1d85-724d-42a3-889f-2e2362bcaf23
description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
references:
    - https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html
tags:
    - attack.discovery
    - attack.t1087
status: experimental
author: Samir Bousseaden
logsource:
    product: windows
    service: security
    definition: 'Requirements: enable Object Access SAM on your Domain Controllers'
detection:
    selection:
        EventID: 4661
        ObjectType:
        - 'SAM_USER'
        - 'SAM_GROUP'
        ObjectName:
         - '*-512'
         - '*-502'
         - '*-500'
         - '*-505'
         - '*-519'
         - '*-520'
         - '*-544'
         - '*-551'
         - '*-555'
         - '*admin*'
    condition: selection
falsepositives:
    - if source account name is not an admin then its super suspicious
level: high

```





### splunk
    
```
(EventID="4661" (ObjectType="SAM_USER" OR ObjectType="SAM_GROUP") (ObjectName="*-512" OR ObjectName="*-502" OR ObjectName="*-500" OR ObjectName="*-505" OR ObjectName="*-519" OR ObjectName="*-520" OR ObjectName="*-544" OR ObjectName="*-551" OR ObjectName="*-555" OR ObjectName="*admin*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[AD Privileged Users or Groups Reconnaissance]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: AD Privileged Users or Groups Reconnaissance status: experimental \
description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs \
references: ['https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html'] \
tags: ['attack.discovery', 'attack.t1087'] \
author: Samir Bousseaden \
date:  \
falsepositives: ['if source account name is not an admin then its super suspicious'] \
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
description = Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4661" (ObjectType="SAM_USER" OR ObjectType="SAM_GROUP") (ObjectName="*-512" OR ObjectName="*-502" OR ObjectName="*-500" OR ObjectName="*-505" OR ObjectName="*-519" OR ObjectName="*-520" OR ObjectName="*-544" OR ObjectName="*-551" OR ObjectName="*-555" OR ObjectName="*admin*")) | stats values(*) AS * by _time | search NOT [| inputlookup AD_Privileged_Users_or_Groups_Reconnaissance_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1087,level=high"
```
