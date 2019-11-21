| Title                | SAM Dump to AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: experimental
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
tags:
    - attack.credential_access
    - attack.t1003
author: Florian Roth
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        EventID: 16
    keywords:
        Message:
            - '*\AppData\Local\Temp\SAM-*.dmp *'
    condition: all of them
falsepositives:
    - Penetration testing
level: high

```





### splunk
    
```
(EventID="16" (Message="*\\\\AppData\\\\Local\\\\Temp\\\\SAM-*.dmp *"))
```



