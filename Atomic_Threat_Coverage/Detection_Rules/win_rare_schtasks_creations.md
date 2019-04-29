| Title                | Rare Schtasks Creations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Software installation</li><li>Software updates</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Rare Schtasks Creations
description: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code
status: experimental
author: Florian Roth
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1053
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection (not in the baseline recommendations by Microsoft). We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection:
        EventID: 4698
    timeframe: 7d
    condition: selection | count() by TaskName < 5 
falsepositives: 
    - Software installation
    - Software updates
level: low

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
grep -P '^4698'
```



