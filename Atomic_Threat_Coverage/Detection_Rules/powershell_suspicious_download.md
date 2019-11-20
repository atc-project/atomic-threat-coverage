| Title                | Suspicious PowerShell Download                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell download command                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>PowerShell scripts that download content from the Internet</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Download
id: 65531a81-a694-4e31-ae04-f8ba5bc33759
status: experimental
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        Message:
            - '*System.Net.WebClient).DownloadString(*'
            - '*system.net.webclient).downloadfile(*'
    condition: keywords
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium

```





### splunk
    
```
(Message="*System.Net.WebClient).DownloadString(*" OR Message="*system.net.webclient).downloadfile(*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Download]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PowerShell Download status: experimental \
description: Detects suspicious PowerShell download command \
references:  \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth \
date:  \
falsepositives: ['PowerShell scripts that download content from the Internet'] \
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
description = Detects suspicious PowerShell download command
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Message="*System.Net.WebClient).DownloadString(*" OR Message="*system.net.webclient).downloadfile(*") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PowerShell_Download_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=medium"
```
