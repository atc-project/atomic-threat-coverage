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






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Network Sniffing]
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
title: Network Sniffing status: experimental \
description: Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. \
references: ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml'] \
tags: ['attack.credential_access', 'attack.discovery', 'attack.t1040'] \
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
description = Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\tshark.exe" CommandLine="*-i*") OR Image="*\\windump.exe") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine,host | search NOT [| inputlookup Network_Sniffing_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.discovery,sigma_tag=attack.t1040,level=low"
```
