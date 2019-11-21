| Title                | Data Compressed                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1002: Data Compressed](../Triggers/T1002.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>highly likely if archive ops are done via PS</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Data Compressed
id: 6dc5d284-69ea-42cf-9311-fb1c3932a69a
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount
    of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
        keywords|contains|all: 
            - '-Recurse'
            - '|'
            - 'Compress-Archive'
    condition: selection
falsepositives:
    - highly likely if archive ops are done via PS
level: low
tags:
    - attack.exfiltration
    - attack.t1002

```





### splunk
    
```
(EventID="4104" keywords="*-Recurse*" keywords="*|*" keywords="*Compress-Archive*")
```



