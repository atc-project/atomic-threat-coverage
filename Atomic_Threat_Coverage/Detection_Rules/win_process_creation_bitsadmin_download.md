| Title                | Bitsadmin Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of bitsadmin downloading a file                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1197: BITS Jobs](../Triggers/T1197.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Some legitimate apps use this, but limited.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin](https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin)</li><li>[https://isc.sans.edu/diary/22264](https://isc.sans.edu/diary/22264)</li></ul>  |
| Author               | Michael Haag |
| Other Tags           | <ul><li>attack.s0190</li><li>attack.s0190</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Bitsadmin Download
id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
status: experimental
description: Detects usage of bitsadmin downloading a file
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
author: Michael Haag
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\bitsadmin.exe'
        CommandLine:
            - /transfer
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Some legitimate apps use this, but limited.
level: medium

```





### splunk
    
```
((Image="*\\\\bitsadmin.exe") (CommandLine="/transfer")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Bitsadmin Download]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Bitsadmin Download status: experimental \
description: Detects usage of bitsadmin downloading a file \
references: ['https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin', 'https://isc.sans.edu/diary/22264'] \
tags: ['attack.defense_evasion', 'attack.persistence', 'attack.t1197', 'attack.s0190'] \
author: Michael Haag \
date:  \
falsepositives: ['Some legitimate apps use this, but limited.'] \
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
description = Detects usage of bitsadmin downloading a file
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\bitsadmin.exe") (CommandLine="/transfer")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Bitsadmin_Download_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.persistence,sigma_tag=attack.t1197,sigma_tag=attack.s0190,level=medium"
```
