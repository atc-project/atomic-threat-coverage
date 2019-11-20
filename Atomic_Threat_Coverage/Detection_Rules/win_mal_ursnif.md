| Title                | Ursnif                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects new registry key created by Ursnif malware.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.yoroi.company/research/ursnif-long-live-the-steganography/](https://blog.yoroi.company/research/ursnif-long-live-the-steganography/)</li><li>[https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/](https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/)</li></ul>  |
| Author               | megan201296 |


## Detection Rules

### Sigma rule

```
title: Ursnif
id: 21f17060-b282-4249-ade0-589ea3591558
status: experimental
description: Detects new registry key created by Ursnif malware.
references:
    - https://blog.yoroi.company/research/ursnif-long-live-the-steganography/
    - https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/
tags:
    - attack.execution
    - attack.t1112
author: megan201296
date: 2019/02/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\Software\AppDataLow\Software\Microsoft\\*'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### splunk
    
```
(EventID="13" TargetObject="*\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Ursnif]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Ursnif status: experimental \
description: Detects new registry key created by Ursnif malware. \
references: ['https://blog.yoroi.company/research/ursnif-long-live-the-steganography/', 'https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/'] \
tags: ['attack.execution', 'attack.t1112'] \
author: megan201296 \
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
description = Detects new registry key created by Ursnif malware.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="13" TargetObject="*\\Software\\AppDataLow\\Software\\Microsoft\\*") | stats values(*) AS * by _time | search NOT [| inputlookup Ursnif_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1112,level=critical"
```
