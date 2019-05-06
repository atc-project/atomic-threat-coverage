| Title                | Disabling Windows Event Auditing                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1054: Indicator Blocking](https://attack.mitre.org/techniques/T1054)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0067_4719_system_audit_policy_was_changed](../Data_Needed/DN_0067_4719_system_audit_policy_was_changed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1054: Indicator Blocking](../Triggers/T1054.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://bit.ly/WinLogsZero2Hero](https://bit.ly/WinLogsZero2Hero)</li></ul>                                                          |
| Author               | @neu5ron                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Disabling Windows Event Auditing
description: 'Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario
    where an entity would want to bypass local logging to evade detection when windows event logging is enabled and
    reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure
    that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc".
    Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off
    specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.'
references:
    - https://bit.ly/WinLogsZero2Hero
tags:
    - attack.defense_evasion
    - attack.t1054
author: '@neu5ron'
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Computer Management > Audit Policy Configuration, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Audit Policy Change'
detection:
    selection:
        EventID: 4719
        AuditPolicyChanges: 'removed'
    condition: selection
falsepositives: 
    - Unknown
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
(EventID:"4719" AND AuditPolicyChanges:"removed")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*4719)(?=.*removed))'
```



