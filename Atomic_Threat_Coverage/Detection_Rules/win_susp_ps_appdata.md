| Title                | PowerShell Script Run in AppData                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Administrative scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1082851155481288706](https://twitter.com/JohnLaTwC/status/1082851155481288706)</li><li>[https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03](https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
date: 2019/01/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* /c powershell*\AppData\Local\\*'
            - '* /c powershell*\AppData\Roaming\\*'
    condition: selection
falsepositives:
    - Administrative scripts
level: medium

```





### splunk
    
```
(CommandLine="* /c powershell*\\\\AppData\\\\Local\\\\*" OR CommandLine="* /c powershell*\\\\AppData\\\\Roaming\\\\*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell Script Run in AppData]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell Script Run in AppData status: experimental \
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder \
references: ['https://twitter.com/JohnLaTwC/status/1082851155481288706', 'https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth \
date:  \
falsepositives: ['Administrative scripts'] \
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
description = Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="* /c powershell*\\AppData\\Local\\*" OR CommandLine="* /c powershell*\\AppData\\Roaming\\*") | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_Script_Run_in_AppData_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=medium"
```
