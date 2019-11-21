| Title                | Data Compressed                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>highly likely if rar is default archiver in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount
    of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
        CommandLine|contains|all:
            - ' a '
            - '-r'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
falsepositives:
    - highly likely if rar is default archiver in the monitored environment
level: low
tags:
    - attack.exfiltration
    - attack.t1002

```





### splunk
    
```
(Image="*\\\\rar.exe" CommandLine="* a *" CommandLine="*-r*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```



