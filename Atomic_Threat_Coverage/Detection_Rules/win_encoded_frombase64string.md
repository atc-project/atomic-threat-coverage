| Title                | Encoded FromBase64String                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a base64 encoded FromBase64String keyword in a process command line                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Encoded FromBase64String
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: experimental
description: Detects a base64 encoded FromBase64String keyword in a process command line
author: Florian Roth
date: 2019/08/24
tags:
    - attack.t1086
    - attack.t1140
    - attack.execution
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: '::FromBase64String'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: critical

```





### splunk
    
```
(CommandLine="*OjpGcm9tQmFzZTY0U3RyaW5n*" OR CommandLine="*o6RnJvbUJhc2U2NFN0cmluZ*" OR CommandLine="*6OkZyb21CYXNlNjRTdHJpbm*") | table CommandLine,ParentCommandLine
```



