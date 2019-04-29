| Title                | Suspicious PsExec execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>nothing observed so far</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html](https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PsExec execution
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - '*-stdin'
         - '*-stdout'
         - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives: 
    - nothing observed so far
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
((EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:("*\\-stdin" "*\\-stdout" "*\\-stderr")) AND NOT (EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:"PSEXESVC*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*(?:.*.*-stdin|.*.*-stdout|.*.*-stderr))))(?=.*(?!.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*PSEXESVC.*)))))'
```



