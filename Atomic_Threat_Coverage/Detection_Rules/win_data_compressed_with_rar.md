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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Data Compressed]
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
title: Data Compressed status: experimental \
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network \
references: ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml'] \
tags: ['attack.exfiltration', 'attack.t1002'] \
author: Timur Zinniatullin, oscd.community \
date:  \
falsepositives: ['highly likely if rar is default archiver in the monitored environment'] \
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
description = An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\rar.exe" CommandLine="* a *" CommandLine="*-r*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine,host | search NOT [| inputlookup Data_Compressed_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.exfiltration,sigma_tag=attack.t1002,level=low"
```
