| Title                | Local accounts discovery                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Local accounts, System Owner/User discovery using operating systems utilities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1033: System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)</li><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1033: System Owner/User Discovery](../Triggers/T1033.md)</li><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrator or user enumerates local users for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Local accounts discovery
id: 502b42de-4306-40b4-9596-6f590c81f073
status: experimental
description: Local accounts, System Owner/User discovery using operating systems utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
      - Image|endswith: '\whoami.exe'
      - Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'useraccount'
            - 'get'
      - Image|endswith: 
            - '\quser.exe'
            - '\qwinsta.exe'
      - Image|endswith: '\cmdkey.exe'
        CommandLine|contains: '/list'
      - Image|endswith: '\cmd.exe'
        CommandLine|contains|all: 
            - '/c'
            - 'dir'
            - '\Users\'
    selection_2:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'user'
    filter:
        CommandLine|contains:
            - '/domain'       # local account discovery only
            - '/add'          # discovery only
            - '/delete'       # discovery only
            - '/active'       # discovery only
            - '/expires'      # discovery only
            - '/passwordreq'  # discovery only
            - '/scriptpath'   # discovery only
            - '/times'        # discovery only
            - '/workstations' # discovery only
    condition: selection_1 or ( selection_2 and not filter )
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
falsepositives:
     - Legitimate administrator or user enumerates local users for legitimate reason
level: low
tags:
    - attack.discovery
    - attack.t1033
    - attack.t1087

```





### splunk
    
```
((Image="*\\\\whoami.exe" OR (Image="*\\\\wmic.exe" CommandLine="*useraccount*" CommandLine="*get*") OR (Image="*\\\\quser.exe" OR Image="*\\\\qwinsta.exe") OR (Image="*\\\\cmdkey.exe" CommandLine="*/list*") OR (Image="*\\\\cmd.exe" CommandLine="*/c*" CommandLine="*dir*" CommandLine="*\\\\Users\\*")) OR (((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*user*") NOT ((CommandLine="*/domain*" OR CommandLine="*/add*" OR CommandLine="*/delete*" OR CommandLine="*/active*" OR CommandLine="*/expires*" OR CommandLine="*/passwordreq*" OR CommandLine="*/scriptpath*" OR CommandLine="*/times*" OR CommandLine="*/workstations*")))) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```



