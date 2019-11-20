| Title                | Powershell AMSI Bypass via .NET Reflection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Request to amsiInitFailed that can be used to disable AMSI Scanning                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/mattifestation/status/735261176745988096](https://twitter.com/mattifestation/status/735261176745988096)</li><li>[https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120](https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Powershell AMSI Bypass via .NET Reflection
id: 30edb182-aa75-42c0-b0a9-e998bb29067c
status: experimental
description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
references:
    - https://twitter.com/mattifestation/status/735261176745988096
    - https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1086
author: Markus Neis
date: 2018/08/17
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*System.Management.Automation.AmsiUtils*'
    selection2:
        CommandLine:
            - '*amsiInitFailed*'
    condition: selection1 and selection2
    falsepositives:
        - Potential Admin Activity
level: high

```





### splunk
    
```
((CommandLine="*System.Management.Automation.AmsiUtils*") (CommandLine="*amsiInitFailed*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Powershell AMSI Bypass via .NET Reflection]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Powershell AMSI Bypass via .NET Reflection status: experimental \
description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning \
references: ['https://twitter.com/mattifestation/status/735261176745988096', 'https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120'] \
tags: ['attack.execution', 'attack.defense_evasion', 'attack.t1086'] \
author: Markus Neis \
date:  \
falsepositives:  \
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
description = Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((CommandLine="*System.Management.Automation.AmsiUtils*") (CommandLine="*amsiInitFailed*")) | stats values(*) AS * by _time | search NOT [| inputlookup Powershell_AMSI_Bypass_via_.NET_Reflection_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.defense_evasion,sigma_tag=attack.t1086,level=high"
```
