| Title                | Java Running with Remote Debugging                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a JAVA process running with remote debugging allowing more than just localhost to connect                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1046: Network Service Scanning](../Triggers/T1046.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Java Running with Remote Debugging
id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
author: Florian Roth
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*transport=dt_socket,address=*'
    exclusion:
        - CommandLine: '*address=127.0.0.1*'
        - CommandLine: '*address=localhost*'
    condition: selection and not exclusion
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### splunk
    
```
(CommandLine="*transport=dt_socket,address=*" NOT (CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Java Running with Remote Debugging]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Java Running with Remote Debugging status:  \
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect \
references:  \
tags: ['attack.discovery', 'attack.t1046'] \
author: Florian Roth \
date:  \
falsepositives: ['unknown'] \
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
description = Detects a JAVA process running with remote debugging allowing more than just localhost to connect
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*transport=dt_socket,address=*" NOT (CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Java_Running_with_Remote_Debugging_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1046,level=medium"
```
