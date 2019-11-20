| Title                | Detects local user creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| Data Needed          | <ul><li>[DN_0086_4720_user_account_was_created](../Data_Needed/DN_0086_4720_user_account_was_created.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Domain Controller Logs</li><li>Local accounts managed by privileged account management tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/](https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/)</li></ul>  |
| Author               | Patrick Bareiss |


## Detection Rules

### Sigma rule

```
title: Detects local user creation
id: 66b6be3d-55d0-4f47-9855-d69df21740ea
description: Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows
    server logs and not on your DC logs.
status: experimental
tags:
    - attack.persistence
    - attack.t1136
references:
    - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/
author: Patrick Bareiss
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
fields:
    - EventCode
    - AccountName
    - AccountDomain
falsepositives: 
    - Domain Controller Logs
    - Local accounts managed by privileged account management tools
level: low



```





### splunk
    
```
EventID="4720" | table EventCode,AccountName,AccountDomain
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Detects local user creation]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:  \\\nEventCode: $result.EventCode$ \\\nAccountName: $result.AccountName$ \\\nAccountDomain: $result.AccountDomain$  \\\ntitle: Detects local user creation status: experimental \\\ndescription: Detects local user creation on windows servers, which shouldn\'t happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs. \\\nreferences: [\'https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/\'] \\\ntags: [\'attack.persistence\', \'attack.t1136\'] \\\nauthor: Patrick Bareiss \\\ndate:  \\\nfalsepositives: [\'Domain Controller Logs\', \'Local accounts managed by privileged account management tools\'] \\\nlevel: low\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects local user creation on windows servers, which shouldn\'t happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = EventID="4720" | table EventCode,AccountName,AccountDomain,host | search NOT [| inputlookup Detects_local_user_creation_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1136,level=low"\n\n\n'
```
