| Title                | Application Whitelisting bypass via dxcap.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of of Dxcap.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate execution of dxcap.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml)</li><li>[https://twitter.com/harr0ey/status/992008180904419328](https://twitter.com/harr0ey/status/992008180904419328)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting bypass via dxcap.exe
id: 60f16a96-db70-42eb-8f76-16763e333590
status: experimental
description: Detects execution of of Dxcap.exe
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
    - https://twitter.com/harr0ey/status/992008180904419328
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
        Image|endswith: '\dxcap.exe'
        CommandLine|contains|all:
            - '-c'
            - '.exe'
    condition: selection
falsepositives:
    - Legitimate execution of dxcap.exe by legitimate user

```





### splunk
    
```
(Image="*\\\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Application Whitelisting bypass via dxcap.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Application Whitelisting bypass via dxcap.exe status: experimental \
description: Detects execution of of Dxcap.exe \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml', 'https://twitter.com/harr0ey/status/992008180904419328'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community \
date:  \
falsepositives: ['Legitimate execution of dxcap.exe by legitimate user'] \
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
description = Detects execution of of Dxcap.exe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*") | stats values(*) AS * by _time | search NOT [| inputlookup Application_Whitelisting_bypass_via_dxcap.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=medium"
```
