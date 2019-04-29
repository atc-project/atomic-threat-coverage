| Title                | RDP Sensitive Settings Changed                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects changes to RDP terminal service sensitive settings                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html](https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: RDP Sensitive Settings Changed
description: Detects changes to RDP terminal service sensitive settings
references:
    - https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
date: 2019/04/03
author: Samir Bousseaden
logsource:
   product: windows
   service: sysmon
detection:
    selection_reg:
        EventID: 13 
        TargetObject: 
            - '*\services\TermService\Parameters\ServiceDll*'
            - '*\Control\Terminal Server\fSingleSessionPerUser*'
            - '*\Control\Terminal Server\fDenyTSConnections*'
    condition: selection_reg
tags:
    - attack.defense_evasion
falsepositives:
    - unknown
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
(EventID:"13" AND TargetObject:("*\\\\services\\\\TermService\\\\Parameters\\\\ServiceDll*" "*\\\\Control\\\\Terminal Server\\\\fSingleSessionPerUser*" "*\\\\Control\\\\Terminal Server\\\\fDenyTSConnections*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\services\\TermService\\Parameters\\ServiceDll.*|.*.*\\Control\\Terminal Server\\fSingleSessionPerUser.*|.*.*\\Control\\Terminal Server\\fDenyTSConnections.*)))'
```



