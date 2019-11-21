| Title                | Persistence and Execution at scale via GPO scheduled task                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect lateral movement using GPO scheduled task, ususally used to deploy ransomware at scale                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://twitter.com/menasec1/status/1106899890377052160](https://twitter.com/menasec1/status/1106899890377052160)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Persistence and Execution at scale via GPO scheduled task
id: a8f29a7b-b137-4446-80a0-b804272f3da2
description: Detect lateral movement using GPO scheduled task, ususally used to deploy ransomware at scale
author: Samir Bousseaden
references:
    - https://twitter.com/menasec1/status/1106899890377052160
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1053
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\SYSVOL
        RelativeTargetName: '*ScheduledTasks.xml'
        Accesses: '*WriteData*'
    condition: selection
falsepositives: 
    - if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks
level: high

```





### splunk
    
```
(EventID="5145" ShareName="\\\\*\\\\SYSVOL" RelativeTargetName="*ScheduledTasks.xml" Accesses="*WriteData*")
```



