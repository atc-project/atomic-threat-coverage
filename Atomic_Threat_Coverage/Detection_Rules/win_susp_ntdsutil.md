| Title                | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>NTDS maintenance</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)
id: 2afafd61-6aae-4df4-baed-139fa1f4c345
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
status: experimental
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm
author: Thomas Patzke
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\ntdsutil*'
    condition: selection
falsepositives:
    - NTDS maintenance
level: high

```





### splunk
    
```
CommandLine="*\\\\ntdsutil*"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) status: experimental \
description: Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT) \
references: ['https://jpcertcc.github.io/ToolAnalysisResultSheet/details/ntdsutil.htm'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Thomas Patzke \
date:  \
falsepositives: ['NTDS maintenance'] \
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
description = Detects execution of ntdsutil.exe, which can be used for various attacks against the NTDS database (NTDS.DIT)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = CommandLine="*\\ntdsutil*" | stats values(*) AS * by _time | search NOT [| inputlookup Invocation_of_Active_Directory_Diagnostic_Tool_ntdsutil.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"
```
