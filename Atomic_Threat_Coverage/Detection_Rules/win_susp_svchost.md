| Title                | Suspicious Svchost Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious svchost process start                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Svchost Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: experimental
description: Detects a suspicious svchost process start
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2017/08/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\svchost.exe'
    filter:
        ParentImage:
            - '*\services.exe'
            - '*\MsMpEng.exe'
            - '*\Mrt.exe'
            - '*\rpcnet.exe'
    filter_null:
        ParentImage: null
    condition: selection and not filter and not filter_null
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
((Image="*\\\\svchost.exe" NOT ((ParentImage="*\\\\services.exe" OR ParentImage="*\\\\MsMpEng.exe" OR ParentImage="*\\\\Mrt.exe" OR ParentImage="*\\\\rpcnet.exe"))) NOT (NOT ParentImage="*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Svchost Process]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Suspicious Svchost Process status: experimental \
description: Detects a suspicious svchost process start \
references:  \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
date:  \
falsepositives: ['Unknown'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects a suspicious svchost process start
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\svchost.exe" NOT ((ParentImage="*\\services.exe" OR ParentImage="*\\MsMpEng.exe" OR ParentImage="*\\Mrt.exe" OR ParentImage="*\\rpcnet.exe"))) NOT (NOT ParentImage="*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Suspicious_Svchost_Process_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
