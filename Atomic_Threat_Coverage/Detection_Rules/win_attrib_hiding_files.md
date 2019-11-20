| Title                | Hiding files with attrib.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of attrib.exe to hide files from users.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1158: Hidden Files and Directories](https://attack.mitre.org/techniques/T1158)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1158: Hidden Files and Directories](../Triggers/T1158.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)</li><li>msiexec.exe hiding desktop.ini</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: Hiding files with attrib.exe
id: 4281cb20-2994-4580-aa63-c8b86d019934
status: experimental
description: Detects usage of attrib.exe to hide files from users.
author: Sami Ruohonen
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\attrib.exe'
        CommandLine: '* +h *'
    ini:
        CommandLine: '*\desktop.ini *'
    intel:
        ParentImage: '*\cmd.exe'
        CommandLine: +R +H +S +A \\*.cui
        ParentCommandLine: C:\WINDOWS\system32\\*.bat
    condition: selection and not (ini or intel)
fields:
    - CommandLine
    - ParentCommandLine
    - User
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1158
falsepositives:
    - igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
    - msiexec.exe hiding desktop.ini
level: low

```





### splunk
    
```
((Image="*\\\\attrib.exe" CommandLine="* +h *") NOT ((CommandLine="*\\\\desktop.ini *" OR (ParentImage="*\\\\cmd.exe" CommandLine="+R +H +S +A \\\\*.cui" ParentCommandLine="C:\\\\WINDOWS\\\\system32\\\\*.bat")))) | table CommandLine,ParentCommandLine,User
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Hiding files with attrib.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$ \
User: $result.User$  \
title: Hiding files with attrib.exe status: experimental \
description: Detects usage of attrib.exe to hide files from users. \
references:  \
tags: ['attack.defense_evasion', 'attack.persistence', 'attack.t1158'] \
author: Sami Ruohonen \
date:  \
falsepositives: ['igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)', 'msiexec.exe hiding desktop.ini'] \
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
description = Detects usage of attrib.exe to hide files from users.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\attrib.exe" CommandLine="* +h *") NOT ((CommandLine="*\\desktop.ini *" OR (ParentImage="*\\cmd.exe" CommandLine="+R +H +S +A \\*.cui" ParentCommandLine="C:\\WINDOWS\\system32\\*.bat")))) | table CommandLine,ParentCommandLine,User,host | search NOT [| inputlookup Hiding_files_with_attrib.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.persistence,sigma_tag=attack.t1158,level=low"
```
