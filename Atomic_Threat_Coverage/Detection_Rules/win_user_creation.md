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



