| Title                | Possible Shim Database Persistence via sdbinst.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1138: Application Shimming](https://attack.mitre.org/techniques/T1138)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1138: Application Shimming](../Triggers/T1138.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Possible Shim Database Persistence via sdbinst.exe
id: 517490a7-115a-48c6-8862-1a481504d5a8
status: experimental
description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
tags:
    - attack.persistence
    - attack.t1138
author: Markus Neis
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\sdbinst.exe'
        CommandLine:
            - '*.sdb*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
((Image="*\\\\sdbinst.exe") (CommandLine="*.sdb*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Shim Database Persistence via sdbinst.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Shim Database Persistence via sdbinst.exe status: experimental \
description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications. \
references: ['https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html'] \
tags: ['attack.persistence', 'attack.t1138'] \
author: Markus Neis \
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
description = Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\sdbinst.exe") (CommandLine="*.sdb*")) | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Shim_Database_Persistence_via_sdbinst.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.persistence,sigma_tag=attack.t1138,level=high"
```
