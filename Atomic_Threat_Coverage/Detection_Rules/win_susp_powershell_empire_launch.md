| Title                | Empire PowerShell Launch Parameters                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell command line parameters used in Empire                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165](https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165)</li><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191)</li><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178)</li><li>[https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64](https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Empire PowerShell Launch Parameters
id: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
description: Detects suspicious powershell command line parameters used in Empire
status: experimental
references:
    - https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
author: Florian Roth
date: 2019/04/20
tags:
  - attack.execution
  - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -NoP -sta -NonI -W Hidden -Enc *'
            - '* -noP -sta -w 1 -enc *'
            - '* -NoP -NonI -W Hidden -enc *'
    condition: selection
level: critical

```





### splunk
    
```
(CommandLine="* -NoP -sta -NonI -W Hidden -Enc *" OR CommandLine="* -noP -sta -w 1 -enc *" OR CommandLine="* -NoP -NonI -W Hidden -enc *")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Empire PowerShell Launch Parameters]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Empire PowerShell Launch Parameters status: experimental \
description: Detects suspicious powershell command line parameters used in Empire \
references: ['https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165', 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191', 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178', 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth \
date:  \
falsepositives:  \
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
description = Detects suspicious powershell command line parameters used in Empire
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="* -NoP -sta -NonI -W Hidden -Enc *" OR CommandLine="* -noP -sta -w 1 -enc *" OR CommandLine="* -NoP -NonI -W Hidden -enc *") | stats values(*) AS * by _time | search NOT [| inputlookup Empire_PowerShell_Launch_Parameters_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=critical"
```
