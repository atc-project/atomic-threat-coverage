| Title                | Detection of PowerShell Execution via DLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/p3nt4/PowerShdll/blob/master/README.md](https://github.com/p3nt4/PowerShdll/blob/master/README.md)</li></ul>  |
| Author               | Markus Neis |
| Other Tags           | <ul><li>car.2014-04-003</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Detection of PowerShell Execution via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: experimental
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
references:
    - https://github.com/p3nt4/PowerShdll/blob/master/README.md
tags:
    - attack.execution
    - attack.t1086
    - car.2014-04-003
author: Markus Neis
date: 2018/08/25
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\rundll32.exe'
    selection2:
        Description:
            - '*Windows-Hostprozess (Rundll32)*'
    selection3:
        CommandLine:
            - '*Default.GetString*'
            - '*FromBase64String*'
    condition: (selection1 or selection2) and selection3
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(((Image="*\\\\rundll32.exe") OR (Description="*Windows-Hostprozess (Rundll32)*")) (CommandLine="*Default.GetString*" OR CommandLine="*FromBase64String*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Detection of PowerShell Execution via DLL]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Detection of PowerShell Execution via DLL status: experimental \
description: Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll \
references: ['https://github.com/p3nt4/PowerShdll/blob/master/README.md'] \
tags: ['attack.execution', 'attack.t1086', 'car.2014-04-003'] \
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
description = Detects PowerShell Strings applied to rundllas seen in PowerShdll.dll
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((Image="*\\rundll32.exe") OR (Description="*Windows-Hostprozess (Rundll32)*")) (CommandLine="*Default.GetString*" OR CommandLine="*FromBase64String*")) | stats values(*) AS * by _time | search NOT [| inputlookup Detection_of_PowerShell_Execution_via_DLL_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,sigma_tag=car.2014-04-003,level=high"
```
