| Title                | Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects defence evasion attempt via odbcconf.exe execution to load DLL                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of odbcconf.exe by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml)</li><li>[https://twitter.com/Hexacorn/status/1187143326673330176](https://twitter.com/Hexacorn/status/1187143326673330176)</li></ul>  |
| Author               | Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe
id: 65d2be45-8600-4042-b4c0-577a1ff8a60e
description: Detects defence evasion attempt via odbcconf.exe execution to load DLL
status: experimental
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml
    - https://twitter.com/Hexacorn/status/1187143326673330176
author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community
date: 2019/10/25
modified: 2019/11/07
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\odbcconf.exe'
        CommandLine|contains: 
            - '-f'
            - 'regsvr'
    selection_2:
        ParentImage|endswith: '\odbcconf.exe'
        Image|endswith: '\rundll32.exe'
    condition: selection_1 or selection_2
level: medium
falsepositives:
    - Legitimate use of odbcconf.exe by legitimate user

```





### splunk
    
```
((Image="*\\\\odbcconf.exe" (CommandLine="*-f*" OR CommandLine="*regsvr*")) OR (ParentImage="*\\\\odbcconf.exe" Image="*\\\\rundll32.exe"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Application Whitelisting Bypass via dll loaded by odbcconf.exe status: experimental \
description: Detects defence evasion attempt via odbcconf.exe execution to load DLL \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml', 'https://twitter.com/Hexacorn/status/1187143326673330176'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community \
date:  \
falsepositives: ['Legitimate use of odbcconf.exe by legitimate user'] \
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
description = Detects defence evasion attempt via odbcconf.exe execution to load DLL
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\odbcconf.exe" (CommandLine="*-f*" OR CommandLine="*regsvr*")) OR (ParentImage="*\\odbcconf.exe" Image="*\\rundll32.exe")) | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Application_Whitelisting_Bypass_via_dll_loaded_by_odbcconf.exe_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=medium"
```
