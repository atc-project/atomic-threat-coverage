| Title                | Suspicious PowerShell Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects keywords that could indicate the use of some PowerShell exploitation framework                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Keywords
id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        Message:
            - "*[System.Reflection.Assembly]::Load*"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### splunk
    
```
(Message="*[System.Reflection.Assembly]::Load*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Keywords]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PowerShell Keywords status: experimental \
description: Detects keywords that could indicate the use of some PowerShell exploitation framework \
references: ['https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth \
date:  \
falsepositives: ['Penetration tests'] \
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
description = Detects keywords that could indicate the use of some PowerShell exploitation framework
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Message="*[System.Reflection.Assembly]::Load*") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PowerShell_Keywords_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
