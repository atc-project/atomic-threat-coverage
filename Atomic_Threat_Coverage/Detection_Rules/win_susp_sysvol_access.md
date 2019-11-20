| Title                | Suspicious SYSVOL Domain Group Policy Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Access to Domain Group Policies stored in SYSVOL                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)</li><li>[https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100](https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: experimental
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis
date: 2018/04/09
modified: 2018/12/11
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\SYSVOL\\*\policies\\*'
    condition: selection
falsepositives:
    - administrative activity
level: medium

```





### splunk
    
```
CommandLine="*\\\\SYSVOL\\\\*\\\\policies\\\\*"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious SYSVOL Domain Group Policy Access]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious SYSVOL Domain Group Policy Access status: experimental \
description: Detects Access to Domain Group Policies stored in SYSVOL \
references: ['https://adsecurity.org/?p=2288', 'https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Markus Neis \
date:  \
falsepositives: ['administrative activity'] \
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
description = Detects Access to Domain Group Policies stored in SYSVOL
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = CommandLine="*\\SYSVOL\\*\\policies\\*" | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_SYSVOL_Domain_Group_Policy_Access_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=medium"
```
