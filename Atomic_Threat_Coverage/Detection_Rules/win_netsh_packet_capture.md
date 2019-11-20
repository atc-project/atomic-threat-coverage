| Title                | Capture a Network Trace with netsh.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects capture a network trace via netsh.exe trace functionality                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)</li></ul>  |
| Author               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Capture a Network Trace with netsh.exe
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: experimental
description: Detects capture a network trace via netsh.exe trace functionality
references:
    - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
author: Kutepov Anton, oscd.community
date: 2019/10/24
tags:
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - netsh
            - trace
            - start
    condition: selection    
falsepositives: 
    - Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason
level: medium

```





### splunk
    
```
(CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Capture a Network Trace with netsh.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Capture a Network Trace with netsh.exe status: experimental \
description: Detects capture a network trace via netsh.exe trace functionality \
references: ['https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/'] \
tags: ['attack.discovery', 'attack.t1040'] \
author: Kutepov Anton, oscd.community \
date:  \
falsepositives: ['Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects capture a network trace via netsh.exe trace functionality
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*") | stats values(*) AS * by _time | search NOT [| inputlookup Capture_a_Network_Trace_with_netsh.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1040,level=medium"
```
