| Title                | WMI Backdoor Exchange Transport Agent                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a WMi backdoor in Exchange Transport Agents via WMi event filters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/cglyer/status/1182389676876980224](https://twitter.com/cglyer/status/1182389676876980224)</li><li>[https://twitter.com/cglyer/status/1182391019633029120](https://twitter.com/cglyer/status/1182391019633029120)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: experimental
description: Detects a WMi backdoor in Exchange Transport Agents via WMi event filters
author: Florian Roth
date: 2019/10/11
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
logsource:
    category: process_creation
    product: windows
tags:
    - attack.persistence
    - attack.t1084
detection:
    selection: 
        ParentImage: '*\EdgeTransport.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical


```





### splunk
    
```
ParentImage="*\\\\EdgeTransport.exe"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[WMI Backdoor Exchange Transport Agent]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: WMI Backdoor Exchange Transport Agent status: experimental \
description: Detects a WMi backdoor in Exchange Transport Agents via WMi event filters \
references: ['https://twitter.com/cglyer/status/1182389676876980224', 'https://twitter.com/cglyer/status/1182391019633029120'] \
tags: ['attack.persistence', 'attack.t1084'] \
author: Florian Roth \
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
description = Detects a WMi backdoor in Exchange Transport Agents via WMi event filters
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ParentImage="*\\EdgeTransport.exe" | stats values(*) AS * by _time | search NOT [| inputlookup WMI_Backdoor_Exchange_Transport_Agent_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1084,level=critical"
```
