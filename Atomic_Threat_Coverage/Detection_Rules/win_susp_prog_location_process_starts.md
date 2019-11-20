| Title                | Suspicious Program Location Process Starts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location Process Starts
id: f50bfd8b-e2a3-4c15-9373-7900b5a4c6d5
status: experimental
description: Detects programs running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
            - '*\Windows\debug\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### splunk
    
```
(Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Perflogs\\\\*" OR Image="*\\\\Windows\\\\Fonts\\\\*" OR Image="*\\\\Windows\\\\IME\\\\*" OR Image="*\\\\Windows\\\\addins\\\\*" OR Image="*\\\\Windows\\\\debug\\\\*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Program Location Process Starts]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Program Location Process Starts status: experimental \
description: Detects programs running in suspicious files system locations \
references: ['https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo'] \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
date:  \
falsepositives: ['unknown'] \
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
description = Detects programs running in suspicious files system locations
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\$Recycle.bin" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*" OR Image="*\\Windows\\debug\\*") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Program_Location_Process_Starts_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
