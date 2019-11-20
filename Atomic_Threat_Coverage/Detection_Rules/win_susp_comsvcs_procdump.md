| Title                | Process dump via comsvcs DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process memory dump via comsvcs.dll and rundll32                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)</li><li>[https://twitter.com/SBousseaden/status/1167417096374050817](https://twitter.com/SBousseaden/status/1167417096374050817)</li></ul>  |
| Author               | Modexp (idea) |


## Detection Rules

### Sigma rule

```
title: Process dump via comsvcs DLL
id: 09e6d5c0-05b8-4ff8-9eeb-043046ec774c
status: experimental
description: Detects process memory dump via comsvcs.dll and rundll32
references:
    - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
    - https://twitter.com/SBousseaden/status/1167417096374050817
author: Modexp (idea)
date: 2019/09/02
logsource:
    category: process_creation
    product: windows
detection:
    rundll_image:
        Image: '*\rundll32.exe'
    rundll_ofn:
        OriginalFileName: 'RUNDLL32.EXE'
    selection:
        CommandLine:
            - '*comsvcs*MiniDump*full*'
            - '*comsvcs*MiniDumpW*full*'
    condition: (rundll_image or rundll_ofn) and selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.credential_access
    - attack.t1003
falsepositives:
    - unknown
level: medium

```





### splunk
    
```
((Image="*\\\\rundll32.exe" OR OriginalFileName="RUNDLL32.EXE") (CommandLine="*comsvcs*MiniDump*full*" OR CommandLine="*comsvcs*MiniDumpW*full*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Process dump via comsvcs DLL]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Process dump via comsvcs DLL status: experimental \
description: Detects process memory dump via comsvcs.dll and rundll32 \
references: ['https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/', 'https://twitter.com/SBousseaden/status/1167417096374050817'] \
tags: ['attack.credential_access', 'attack.t1003'] \
author: Modexp (idea) \
date:  \
falsepositives: ['unknown'] \
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
description = Detects process memory dump via comsvcs.dll and rundll32
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\rundll32.exe" OR OriginalFileName="RUNDLL32.EXE") (CommandLine="*comsvcs*MiniDump*full*" OR CommandLine="*comsvcs*MiniDumpW*full*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Process_dump_via_comsvcs_DLL_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=medium"
```
