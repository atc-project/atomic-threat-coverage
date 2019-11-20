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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Change Default File Association]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
Image: $result.Image$ \
CommandLine: $result.CommandLine$ \
User: $result.User$ \
LogonGuid: $result.LogonGuid$ \
Hashes: $result.Hashes$ \
ParentProcessGuid: $result.ParentProcessGuid$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Change Default File Association status: experimental \
description: When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened. \
references: ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml'] \
tags: ['attack.persistence', 'attack.t1042'] \
author: Timur Zinniatullin, oscd.community \
date:  \
falsepositives: ['Admin activity'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*assoc*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine,host | search NOT [| inputlookup Change_Default_File_Association_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1042,level=low"
```
