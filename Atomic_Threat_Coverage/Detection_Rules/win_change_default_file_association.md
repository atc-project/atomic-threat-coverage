| Title                | Change Default File Association                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1042: Change Default File Association](https://attack.mitre.org/techniques/T1042)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1042: Change Default File Association](../Triggers/T1042.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Admin activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Change Default File Association
id: 3d3aa6cd-6272-44d6-8afc-7e88dfef7061
status: experimental
description: When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections
    are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc
    utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
          - 'cmd'
          - '/c'
          - 'assoc'
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
    - attack.persistence
    - attack.t1042

```





### splunk
    
```
(CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*assoc*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```



