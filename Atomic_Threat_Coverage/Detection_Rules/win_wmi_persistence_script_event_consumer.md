| Title                | WMI Persistence - Script Event Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI script event consumers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate event consumers</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Script Event Consumer
id: ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e
status: experimental
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: C:\WINDOWS\system32\wbem\scrcons.exe
        ParentImage: C:\Windows\System32\svchost.exe
    condition: selection
falsepositives:
    - Legitimate event consumers
level: high

```





### splunk
    
```
(Image="C:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe" ParentImage="C:\\\\Windows\\\\System32\\\\svchost.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[WMI Persistence - Script Event Consumer]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: WMI Persistence - Script Event Consumer status: experimental \
description: Detects WMI script event consumers \
references: ['https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/'] \
tags: ['attack.execution', 'attack.persistence', 'attack.t1047'] \
author: Thomas Patzke \
date:  \
falsepositives: ['Legitimate event consumers'] \
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
description = Detects WMI script event consumers
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe" ParentImage="C:\\Windows\\System32\\svchost.exe") | stats values(*) AS * by _time | search NOT [| inputlookup WMI_Persistence_-_Script_Event_Consumer_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.persistence,sigma_tag=attack.t1047,level=high"
```
