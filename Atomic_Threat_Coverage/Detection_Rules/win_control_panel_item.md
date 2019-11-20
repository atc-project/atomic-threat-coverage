| Title                | Control Panel Items                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of a control panel item (.cpl) outside of the System32 folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1196: Control Panel Items](../Triggers/T1196.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Kyaw Min Thein |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the use of a control panel item (.cpl) outside of the System32 folder
reference:
    - https://attack.mitre.org/techniques/T1196/
tags:
    - attack.execution
    - attack.t1196
    - attack.defense_evasion
author: Kyaw Min Thein
date: 2019/08/27
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    condition: selection and not filter
falsepositives:
    - Unknown

```





### splunk
    
```
(CommandLine="*.cpl" NOT ((CommandLine="*\\\\System32\\\\*" OR CommandLine="*%System%*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Control Panel Items]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Control Panel Items status: experimental \
description: Detects the use of a control panel item (.cpl) outside of the System32 folder \
references:  \
tags: ['attack.execution', 'attack.t1196', 'attack.defense_evasion'] \
author: Kyaw Min Thein \
date:  \
falsepositives: ['Unknown'] \
level: critical
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects the use of a control panel item (.cpl) outside of the System32 folder
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*.cpl" NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*"))) | stats values(*) AS * by _time | search NOT [| inputlookup Control_Panel_Items_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1196,sigma_tag=attack.defense_evasion,level=critical"
```
