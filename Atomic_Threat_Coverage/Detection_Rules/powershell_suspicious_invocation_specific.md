| Title                | Suspicious PowerShell Invocations - Specific                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Specific
id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule)
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        Message:
            - '* -nop -w hidden -c * [Convert]::FromBase64String*'
            - '* -w hidden -noni -nop -c "iex(New-Object*'
            - '* -w hidden -ep bypass -Enc*'
            - '*powershell.exe reg add HKCU\software\microsoft\windows\currentversion\run*'
            - '*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*'
            - '*iex(New-Object Net.WebClient).Download*'
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### splunk
    
```
(Message="* -nop -w hidden -c * [Convert]::FromBase64String*" OR Message="* -w hidden -noni -nop -c \\"iex(New-Object*" OR Message="* -w hidden -ep bypass -Enc*" OR Message="*powershell.exe reg add HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run*" OR Message="*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*" OR Message="*iex(New-Object Net.WebClient).Download*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Invocations - Specific]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PowerShell Invocations - Specific status: experimental \
description: Detects suspicious PowerShell invocation command parameters \
references:  \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth (rule) \
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
description = Detects suspicious PowerShell invocation command parameters
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Message="* -nop -w hidden -c * [Convert]::FromBase64String*" OR Message="* -w hidden -noni -nop -c \"iex(New-Object*" OR Message="* -w hidden -ep bypass -Enc*" OR Message="*powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run*" OR Message="*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*" OR Message="*iex(New-Object Net.WebClient).Download*") | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PowerShell_Invocations_-_Specific_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
