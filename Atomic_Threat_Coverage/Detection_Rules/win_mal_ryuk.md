| Title                | Ryuk Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Ryuk Ransomware command lines                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/](https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/)</li></ul>  |
| Author               | Vasiliy Burov |


## Detection Rules

### Sigma rule

```
title: Ryuk Ransomware
id: 0acaad27-9f02-4136-a243-c357202edd74
description: Detects Ryuk Ransomware command lines
status: experimental
references:
    - https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/
author: Vasiliy Burov
date: 2019/08/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\net.exe stop "samss" *'
            - '*\net.exe stop "audioendpointbuilder" *'
            - '*\net.exe stop "unistoresvc_?????" *'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### splunk
    
```
(CommandLine="*\\\\net.exe stop \\"samss\\" *" OR CommandLine="*\\\\net.exe stop \\"audioendpointbuilder\\" *" OR CommandLine="*\\\\net.exe stop \\"unistoresvc_?????\\" *")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Ryuk Ransomware]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Ryuk Ransomware status: experimental \
description: Detects Ryuk Ransomware command lines \
references: ['https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/'] \
tags:  \
author: Vasiliy Burov \
date:  \
falsepositives: ['Unlikely'] \
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
description = Detects Ryuk Ransomware command lines
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\net.exe stop \"samss\" *" OR CommandLine="*\\net.exe stop \"audioendpointbuilder\" *" OR CommandLine="*\\net.exe stop \"unistoresvc_?????\" *") | stats values(*) AS * by _time | search NOT [| inputlookup Ryuk_Ransomware_whitelist.csv]
```
