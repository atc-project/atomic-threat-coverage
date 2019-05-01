| Title                | Pass the Hash Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the attack technique pass the hash which is used to move laterally inside the network                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li></ul>                                                          |
| Author               | Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity
status: experimental
description: 'Detects the attack technique pass the hash which is used to move laterally inside the network'
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
author: Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method)
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624, a failed logon attempt would trigger an event ID 4625
detection:
    selection:
        - EventID: 4624
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
        - EventID: 4625
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
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
((LogonType:"3" AND LogonProcessName:"NtLmSsp" AND WorkstationName:"%Workstations%" AND ComputerName:"%Workstations%" AND (EventID:"4624" OR EventID:"4625")) AND NOT (AccountName:"ANONYMOUS LOGON"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*NtLmSsp)(?=.*%Workstations%)(?=.*%Workstations%)(?=.*(?:.*(?:.*4624|.*4625)))))(?=.*(?!.*(?:.*(?=.*ANONYMOUS LOGON)))))'
```



