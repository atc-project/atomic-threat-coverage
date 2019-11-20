| Title                | Suspicious Calculator Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/ItsReallyNick/status/1094080242686312448](https://twitter.com/ItsReallyNick/status/1094080242686312448)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Calculator Usage
id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*\calc.exe *'
    selection2:
        Image: '*\calc.exe'
    filter2:
        Image: '*\Windows\Sys*'
    condition: selection1 or ( selection2 and not filter2 )
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(CommandLine="*\\\\calc.exe *" OR (Image="*\\\\calc.exe" NOT (Image="*\\\\Windows\\\\Sys*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Calculator Usage]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Calculator Usage status: experimental \
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion \
references: ['https://twitter.com/ItsReallyNick/status/1094080242686312448'] \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
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
description = Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\calc.exe *" OR (Image="*\\calc.exe" NOT (Image="*\\Windows\\Sys*"))) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Calculator_Usage_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
