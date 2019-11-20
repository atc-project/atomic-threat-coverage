| Title                | Suspicious RASdial Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process related to rasdial.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/subTee/status/891298217907830785](https://twitter.com/subTee/status/891298217907830785)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious RASdial Activity
id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
description: Detects suspicious process related to rasdial.exe
status: experimental
references:
    - https://twitter.com/subTee/status/891298217907830785
author: juju4
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - rasdial
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(CommandLine="rasdial")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious RASdial Activity]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious RASdial Activity status: experimental \
description: Detects suspicious process related to rasdial.exe \
references: ['https://twitter.com/subTee/status/891298217907830785'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1064'] \
author: juju4 \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
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
description = Detects suspicious process related to rasdial.exe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="rasdial") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_RASdial_Activity_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1064,level=medium"
```
