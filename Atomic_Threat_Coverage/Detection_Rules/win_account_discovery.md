| Title                | AD Privileged Users or Groups Reconnaissance                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>if source account name is not an admin then its super suspicious</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html](https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: AD Privileged Users or Groups Reconnaissance
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





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"4661" AND ObjectType:("SAM_USER" "SAM_GROUP") AND ObjectName:("*\\-512" "*\\-502" "*\\-500" "*\\-505" "*\\-519" "*\\-520" "*\\-544" "*\\-551" "*\\-555" "*admin*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*4661)(?=.*(?:.*SAM_USER|.*SAM_GROUP))(?=.*(?:.*.*-512|.*.*-502|.*.*-500|.*.*-505|.*.*-519|.*.*-520|.*.*-544|.*.*-551|.*.*-555|.*.*admin.*)))'
```



