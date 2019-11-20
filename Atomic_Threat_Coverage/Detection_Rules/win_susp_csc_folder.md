| Title                | Suspicious Csc.exe Source File Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1500: Compile After Delivery](https://attack.mitre.org/techniques/T1500)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1500: Compile After Delivery](../Triggers/T1500.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/](https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/)</li><li>[https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf](https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf)</li><li>[https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/](https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Csc.exe Source File Folder
id: dcaa3f04-70c3-427a-80b4-b870d73c94c4
description: Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)
status: experimental
references:
    - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
    - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
    - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
author: Florian Roth
date: 2019/08/24
modified: 2019/08/31
tags:
    - attack.defense_evasion
    - attack.t1500
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe'
        CommandLine: 
            - '*\AppData\\*'
            - '*\Windows\Temp\\*'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(Image="*\\\\csc.exe" (CommandLine="*\\\\AppData\\\\*" OR CommandLine="*\\\\Windows\\\\Temp\\\\*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Csc.exe Source File Folder]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Csc.exe Source File Folder status: experimental \
description: Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData) \
references: ['https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/', 'https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf', 'https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/'] \
tags: ['attack.defense_evasion', 'attack.t1500'] \
author: Florian Roth \
date:  \
falsepositives: ['Unkown'] \
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
description = Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\csc.exe" (CommandLine="*\\AppData\\*" OR CommandLine="*\\Windows\\Temp\\*")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Csc.exe_Source_File_Folder_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1500,level=high"
```
