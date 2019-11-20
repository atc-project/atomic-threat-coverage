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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Query Registry]
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
title: Query Registry status: experimental \
description: Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. \
references: ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml'] \
tags: ['attack.discovery', 'attack.t1012', 'attack.t1007'] \
author: Timur Zinniatullin, oscd.community \
date:  \
falsepositives:  \
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
description = Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\reg.exe" (CommandLine="*currentVersion\\windows*" OR CommandLine="*currentVersion\\runServicesOnce*" OR CommandLine="*currentVersion\\runServices*" OR CommandLine="*winlogon\*" OR CommandLine="*currentVersion\\shellServiceObjectDelayLoad*" OR CommandLine="*currentVersion\\runOnce*" OR CommandLine="*currentVersion\\runOnceEx*" OR CommandLine="*currentVersion\\run*" OR CommandLine="*currentVersion\\policies\\explorer\\run*" OR CommandLine="*currentcontrolset\\services*")) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine,host | search NOT [| inputlookup Query_Registry_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1012,sigma_tag=attack.t1007,level=low"
```
