| Title                | Encoded IEX                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a base64 encoded IEX command string in a process command line                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
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
title: Encoded IEX
id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: experimental
description: Detects a base64 encoded IEX command string in a process command line
author: Florian Roth
date: 2019/08/23
tags:
    - attack.t1086
    - attack.t1140
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: 
          - 'IEX (['
          - 'iex (['
          - 'iex (New'
          - 'IEX (New'
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
(CommandLine="*SUVYIChb*" OR CommandLine="*lFWCAoW*" OR CommandLine="*JRVggKF*" OR CommandLine="*aWV4IChb*" OR CommandLine="*lleCAoW*" OR CommandLine="*pZXggKF*" OR CommandLine="*aWV4IChOZX*" OR CommandLine="*lleCAoTmV3*" OR CommandLine="*pZXggKE5ld*" OR CommandLine="*SUVYIChOZX*" OR CommandLine="*lFWCAoTmV3*" OR CommandLine="*JRVggKE5ld*") | table CommandLine,ParentCommandLine
```



