| Title                | MSHTA spwaned by SVCHOST as seen in LethalHTA                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects MSHTA.EXE spwaned by SVCHOST described in report                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: MSHTA spwaned by SVCHOST as seen in LethalHTA
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: experimental
description: Detects MSHTA.EXE spwaned by SVCHOST described in report
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
author: Markus Neis
date: 2018/06/07
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(ParentImage="*\\\\svchost.exe" Image="*\\\\mshta.exe")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[MSHTA spwaned by SVCHOST as seen in LethalHTA]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: MSHTA spwaned by SVCHOST as seen in LethalHTA status: experimental \
description: Detects MSHTA.EXE spwaned by SVCHOST described in report \
references: ['https://codewhitesec.blogspot.com/2018/07/lethalhta.html'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1170'] \
author: Markus Neis \
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
description = Detects MSHTA.EXE spwaned by SVCHOST described in report
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (ParentImage="*\\svchost.exe" Image="*\\mshta.exe") | stats values(*) AS * by _time | search NOT [| inputlookup MSHTA_spwaned_by_SVCHOST_as_seen_in_LethalHTA_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1170,level=high"
```
