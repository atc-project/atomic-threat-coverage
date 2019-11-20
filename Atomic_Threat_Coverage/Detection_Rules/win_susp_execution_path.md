| Title                | Execution in Non-Executable Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious exection from an uncommon folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
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
title: Execution in Non-Executable Folder
id: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
status: experimental
description: Detects a suspicious exection from an uncommon folder
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\All Users\\\\*" OR Image="*\\\\Users\\\\Default\\\\*" OR Image="*\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Perflogs\\\\*" OR Image="*\\\\config\\\\systemprofile\\\\*" OR Image="*\\\\Windows\\\\Fonts\\\\*" OR Image="*\\\\Windows\\\\IME\\\\*" OR Image="*\\\\Windows\\\\addins\\\\*") | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Execution in Non-Executable Folder]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Execution in Non-Executable Folder status: experimental \
description: Detects a suspicious exection from an uncommon folder \
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
description = Detects a suspicious exection from an uncommon folder
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\$Recycle.bin" OR Image="*\\Users\\All Users\\*" OR Image="*\\Users\\Default\\*" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\config\\systemprofile\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*") | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Execution_in_Non-Executable_Folder_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
