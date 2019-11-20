| Title                | Possible Ransomware or unauthorized MBR modifications                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects, possibly, malicious unauthorized usage of bcdedit.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1067: Bootkit](https://attack.mitre.org/techniques/T1067)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li><li>[T1067: Bootkit](../Triggers/T1067.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Possible Ransomware or unauthorized MBR modifications
id: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
status: experimental
description: Detects, possibly, malicious unauthorized usage of bcdedit.exe
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
author: '@neu5ron'
date: 2019/02/07
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.persistence
    - attack.t1067
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName: '*\bcdedit.exe'
        ProcessCommandLine:
            - '*delete*'
            - '*deletevalue*'
            - '*import*'
    condition: selection
level: medium

```





### splunk
    
```
(NewProcessName="*\\\\bcdedit.exe" (ProcessCommandLine="*delete*" OR ProcessCommandLine="*deletevalue*" OR ProcessCommandLine="*import*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Ransomware or unauthorized MBR modifications]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Ransomware or unauthorized MBR modifications status: experimental \
description: Detects, possibly, malicious unauthorized usage of bcdedit.exe \
references: ['https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set'] \
tags: ['attack.defense_evasion', 'attack.t1070', 'attack.persistence', 'attack.t1067'] \
author: @neu5ron \
date:  \
falsepositives:  \
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
description = Detects, possibly, malicious unauthorized usage of bcdedit.exe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (NewProcessName="*\\bcdedit.exe" (ProcessCommandLine="*delete*" OR ProcessCommandLine="*deletevalue*" OR ProcessCommandLine="*import*")) | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Ransomware_or_unauthorized_MBR_modifications_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1070,sigma_tag=attack.persistence,sigma_tag=attack.t1067,level=medium"
```
