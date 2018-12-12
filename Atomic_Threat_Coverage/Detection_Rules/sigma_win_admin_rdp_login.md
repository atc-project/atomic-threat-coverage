| Title        | Admin User Remote Logon |
|:-------------------|:------------------|
| Description        | Detect remote login by Administrator user depending on internal pattern |
| Tags               |   |
| ATT&amp;CK Tactic | ('Lateral Movement', 'TA0008')  |
| ATT&amp;CK Technique | T1078  |
| Dataneeded         | DN_0004_windows_account_logon_4624 |
| Triggering         | T1078: No atomics trigger for this technique |
| Severity Level     | low       |
| False Positives    | Legitimate administrative activity |
| Development Status | experimental      |
| References         | https://car.mitre.org/wiki/CAR-2016-04-005 |
| Author             | juju4      |


## Detection Rules

### Sigma rule

```
title: Admin User Remote Logon
description: Detect remote login by Administrator user depending on internal pattern
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
tags:
    - attack.lateral_movement
    - attack.t1078
status: experimental
author: juju4
logsource:
    product: windows
    service: security
    description: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
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











Graylog

```
b'(EventID:"4624" AND LogonType:"10" AND AuthenticationPackageName:"Negotiate" AND AccountName:"Admin\\-*")\n'
```

