| Title                | Addition of SID History to Active Directory Object                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An attacker can use the SID history attribute to gain additional privileges.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1178: SID-History Injection](https://attack.mitre.org/techniques/T1178)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1178: SID-History Injection](../Triggers/T1178.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Migration of an account into a new domain</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Addition of SID History to Active Directory Object
status: stable
description: An attacker can use the SID history attribute to gain additional privileges.
references:
    - https://adsecurity.org/?p=1772
author: Thomas Patzke
tags:
    - attack.privilege_escalation
    - attack.t1178
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4765
            - 4766
    condition: selection
falsepositives:
    - Migration of an account into a new domain
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
EventID:("4765" "4766")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*4765|.*4766)'
```



