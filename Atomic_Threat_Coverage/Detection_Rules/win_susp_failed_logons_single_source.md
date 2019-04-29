| Title                | Multiple Failed Logins with Different Accounts from Single Source System                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious failed logins with different user accounts from a single source system                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Terminal servers</li><li>Jump servers</li><li>Other multiuser systems like Citrix server farms</li><li>Workstations with frequently changing users</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Multiple Failed Logins with Different Accounts from Single Source System
description: Detects suspicious failed logins with different user accounts from a single source system 
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 529
            - 4625
        UserName: '*'
        WorkstationName: '*'
    selection2:
        EventID: 4776
        UserName: '*'
        Workstation: '*'
    timeframe: 24h 
    condition:
        - selection1 | count(UserName) by WorkstationName > 3
        - selection2 | count(UserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users 
level: medium



```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```

```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*529|.*4625))(?=.*.*)(?=.*.*))'
```



