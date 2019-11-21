| Title                | Query Registry                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1007: System Service Discovery](https://attack.mitre.org/techniques/T1007)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1007: System Service Discovery](../Triggers/T1007.md)</li></ul>  |
| Severity Level       | low |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Query Registry
id: 970007b7-ce32-49d0-a4a4-fbef016950bd
status: experimental
description: Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'currentVersion\windows'
            - 'currentVersion\runServicesOnce'
            - 'currentVersion\runServices'
            - 'winlogon\'
            - 'currentVersion\shellServiceObjectDelayLoad'
            - 'currentVersion\runOnce'
            - 'currentVersion\runOnceEx'
            - 'currentVersion\run'
            - 'currentVersion\policies\explorer\run'
            - 'currentcontrolset\services'
    condition: selection
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
    - attack.discovery
    - attack.t1012
    - attack.t1007

```





### splunk
    
```
(Image="*\\\\reg.exe" (CommandLine="*currentVersion\\\\windows*" OR CommandLine="*currentVersion\\\\runServicesOnce*" OR CommandLine="*currentVersion\\\\runServices*" OR CommandLine="*winlogon\\*" OR CommandLine="*currentVersion\\\\shellServiceObjectDelayLoad*" OR CommandLine="*currentVersion\\\\runOnce*" OR CommandLine="*currentVersion\\\\runOnceEx*" OR CommandLine="*currentVersion\\\\run*" OR CommandLine="*currentVersion\\\\policies\\\\explorer\\\\run*" OR CommandLine="*currentcontrolset\\\\services*")) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```



