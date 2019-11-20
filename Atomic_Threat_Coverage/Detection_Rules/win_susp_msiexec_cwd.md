| Title                | Suspicious MsiExec Directory                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious msiexec process starts in an uncommon directory                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/200_okay_/status/1194765831911215104](https://twitter.com/200_okay_/status/1194765831911215104)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious MsiExec Directory
id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: experimental
description: Detects suspicious msiexec process starts in an uncommon directory
references:
    - https://twitter.com/200_okay_/status/1194765831911215104
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/11/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\msiexec.exe'
    filter:
        Image: 
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
            - 'C:\Windows\WinSxS\\*' 
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(Image="*\\\\msiexec.exe" NOT ((Image="C:\\\\Windows\\\\System32\\\\*" OR Image="C:\\\\Windows\\\\SysWOW64\\\\*" OR Image="C:\\\\Windows\\\\WinSxS\\\\*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious MsiExec Directory]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious MsiExec Directory status: experimental \
description: Detects suspicious msiexec process starts in an uncommon directory \
references: ['https://twitter.com/200_okay_/status/1194765831911215104'] \
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
description = Detects suspicious msiexec process starts in an uncommon directory
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\msiexec.exe" NOT ((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*" OR Image="C:\\Windows\\WinSxS\\*"))) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_MsiExec_Directory_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1036,level=high"
```
