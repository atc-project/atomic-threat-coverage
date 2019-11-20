| Title                | SquiblyTwo                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html](https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html)</li><li>[https://twitter.com/mattifestation/status/986280382042595328](https://twitter.com/mattifestation/status/986280382042595328)</li></ul>  |
| Author               | Markus Neis / Florian Roth |


## Detection Rules

### Sigma rule

```
title: SquiblyTwo
id: 8d63dadf-b91b-4187-87b6-34a1114577ea
status: experimental
description: Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash
references:
    - https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html
    - https://twitter.com/mattifestation/status/986280382042595328
tags:
    - attack.defense_evasion
    - attack.t1047
author: Markus Neis / Florian Roth
falsepositives:
    - Unknown
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - wmic * *format:\"http*
            - wmic * /format:'http
            - wmic * /format:http*
    selection2:
        Imphash:
            - 1B1A3F43BF37B5BFE60751F2EE2F326E
            - 37777A96245A3C74EB217308F3546F4C
            - 9D87C9D67CE724033C0B40CC4CA1B206
        CommandLine:
            - '* *format:\"http*'
            - '* /format:''http'
            - '* /format:http*'
    condition: 1 of them

```





### splunk
    
```
(((Image="*\\\\wmic.exe") (CommandLine="wmic * *format:\\\\\\"http*" OR CommandLine="wmic * /format:\'http" OR CommandLine="wmic * /format:http*")) OR ((Imphash="1B1A3F43BF37B5BFE60751F2EE2F326E" OR Imphash="37777A96245A3C74EB217308F3546F4C" OR Imphash="9D87C9D67CE724033C0B40CC4CA1B206") (CommandLine="* *format:\\\\\\"http*" OR CommandLine="* /format:\'http" OR CommandLine="* /format:http*")))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[SquiblyTwo]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: SquiblyTwo status: experimental \
description: Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash \
references: ['https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html', 'https://twitter.com/mattifestation/status/986280382042595328'] \
tags: ['attack.defense_evasion', 'attack.t1047'] \
author: Markus Neis / Florian Roth \
date:  \
falsepositives: ['Unknown'] \
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
description = Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((Image="*\\wmic.exe") (CommandLine="wmic * *format:\\\"http*" OR CommandLine="wmic * /format:'http" OR CommandLine="wmic * /format:http*")) OR ((Imphash="1B1A3F43BF37B5BFE60751F2EE2F326E" OR Imphash="37777A96245A3C74EB217308F3546F4C" OR Imphash="9D87C9D67CE724033C0B40CC4CA1B206") (CommandLine="* *format:\\\"http*" OR CommandLine="* /format:'http" OR CommandLine="* /format:http*"))) | stats values(*) AS * by _time | search NOT [| inputlookup SquiblyTwo_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1047,level=medium"
```
