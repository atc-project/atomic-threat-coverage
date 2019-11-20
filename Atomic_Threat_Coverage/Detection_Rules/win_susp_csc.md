| Title                | Suspicious Parent of Csc.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious parent of csc.exe, which could by a sign of payload delivery                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/SBousseaden/status/1094924091256176641](https://twitter.com/SBousseaden/status/1094924091256176641)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Parent of Csc.exe
id: b730a276-6b63-41b8-bcf8-55930c8fc6ee
description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
status: experimental
references:
    - https://twitter.com/SBousseaden/status/1094924091256176641
author: Florian Roth
date: 2019/02/11
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe*'
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\mshta.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(Image="*\\\\csc.exe*" (ParentImage="*\\\\wscript.exe" OR ParentImage="*\\\\cscript.exe" OR ParentImage="*\\\\mshta.exe"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Parent of Csc.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Parent of Csc.exe status: experimental \
description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery \
references: ['https://twitter.com/SBousseaden/status/1094924091256176641'] \
tags: ['attack.defense_evasion', 'attack.t1036'] \
author: Florian Roth \
date:  \
falsepositives: ['Unkown'] \
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
description = Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\csc.exe*" (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Parent_of_Csc.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
