| Title                | Application Whitelisting bypass via dnx.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Execute C# code located in the consoleapp folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of dnx.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml)</li><li>[https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/](https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting bypass via dnx.exe
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: experimental
description: Execute C# code located in the consoleapp folder
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user

```





### splunk
    
```
Image="*\\\\dnx.exe"
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Application Whitelisting bypass via dnx.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Application Whitelisting bypass via dnx.exe status: experimental \
description: Execute C# code located in the consoleapp folder \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml', 'https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community \
date:  \
falsepositives: ['Legitimate use of dnx.exe by legitimate user'] \
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
description = Execute C# code located in the consoleapp folder
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = Image="*\\dnx.exe" | stats values(*) AS * by _time | search NOT [| inputlookup Application_Whitelisting_bypass_via_dnx.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=medium"
```
