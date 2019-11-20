| Title                | Taskmgr as Parent                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a process from Windows task manager                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Taskmgr as Parent
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: experimental
description: Detects the creation of a process from Windows task manager
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\taskmgr.exe'
    filter:
        Image:
            - '*\resmon.exe'
            - '*\mmc.exe'
            - '*\taskmgr.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```





### splunk
    
```
(ParentImage="*\\\\taskmgr.exe" NOT ((Image="*\\\\resmon.exe" OR Image="*\\\\mmc.exe" OR Image="*\\\\taskmgr.exe"))) | table Image,CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Taskmgr as Parent]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
Image: $result.Image$ \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Taskmgr as Parent status: experimental \
description: Detects the creation of a process from Windows task manager \
references:  \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
date:  \
falsepositives: ['Administrative activity'] \
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
description = Detects the creation of a process from Windows task manager
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (ParentImage="*\\taskmgr.exe" NOT ((Image="*\\resmon.exe" OR Image="*\\mmc.exe" OR Image="*\\taskmgr.exe"))) | table Image,CommandLine,ParentCommandLine,host | search NOT [| inputlookup Taskmgr_as_Parent_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=low"
```
