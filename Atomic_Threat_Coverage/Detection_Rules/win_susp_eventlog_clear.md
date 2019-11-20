| Title                | Suspicious eventlog clear or configuration using wevtutil                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Ecco |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious eventlog clear or configuration using wevtutil
id: cc36992a-4671-4f21-a91d-6c2b72a2edf5
description: Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco
date: 2019/09/26
tags:
    - attack.execution
    - attack.t1070
    - car.2016-04-002
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary_1:
        Image: '*\wevtutil.exe'
    selection_binary_2:
        OriginalFileName: 'wevtutil.exe'
    selection_clear_1:
        CommandLine: '* cl *'
    selection_clear_2:
        CommandLine: '* clear-log *'
    selection_disable_1:
        CommandLine: '* sl *'
    selection_disable_2:
        CommandLine: '* set-log *'
    condition: (1 of selection_binary_*) and (1 of selection_clear_* or 1 of selection_disable_*)
    
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### splunk
    
```
((Image="*\\\\wevtutil.exe" OR OriginalFileName="wevtutil.exe") (CommandLine="* cl *" OR CommandLine="* clear-log *" OR CommandLine="* sl *" OR CommandLine="* set-log *"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious eventlog clear or configuration using wevtutil]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious eventlog clear or configuration using wevtutil status:  \
description: Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others) \
references:  \
tags: ['attack.execution', 'attack.t1070', 'car.2016-04-002'] \
author: Ecco \
date:  \
falsepositives: ['Admin activity', 'Scripts and administrative tools used in the monitored environment'] \
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
description = Detects clearing or configuration of eventlogs uwing wevtutil. Might be used by ransomwares during the attack (seen by NotPetya and others)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\wevtutil.exe" OR OriginalFileName="wevtutil.exe") (CommandLine="* cl *" OR CommandLine="* clear-log *" OR CommandLine="* sl *" OR CommandLine="* set-log *")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_eventlog_clear_or_configuration_using_wevtutil_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1070,sigma_tag=car.2016-04-002,level=high"
```
