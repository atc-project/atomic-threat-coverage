| Title                | Network Sniffing                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Admin activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Network Sniffing
id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: experimental
description: Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary
    may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\tshark.exe'
        CommandLine|contains: '-i'
      - Image|endswith: '\windump.exe'
    condition: selection
falsepositives:
    - Admin activity
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
level: low
tags:
    - attack.credential_access
    - attack.discovery
    - attack.t1040

```





### splunk
    
```
((Image="*\\\\tshark.exe" CommandLine="*-i*") OR Image="*\\\\windump.exe") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```



