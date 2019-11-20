| Title                | PowerShell Credential Prompt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PowerShell calling a credential prompt                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/850381440629981184](https://twitter.com/JohnLaTwC/status/850381440629981184)</li><li>[https://t.co/ezOTGy1a1G](https://t.co/ezOTGy1a1G)</li></ul>  |
| Author               | John Lambert (idea), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell Credential Prompt
id: ca8b77a9-d499-4095-b793-5d5f330d450e
status: experimental
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
tags:
    - attack.execution
    - attack.credential_access    
    - attack.t1086
author: John Lambert (idea), Florian Roth (rule)
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword:
        Message:
            - '*PromptForCredential*'
    condition: all of them
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(EventID="4104" (Message="*PromptForCredential*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell Credential Prompt]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell Credential Prompt status: experimental \
description: Detects PowerShell calling a credential prompt \
references: ['https://twitter.com/JohnLaTwC/status/850381440629981184', 'https://t.co/ezOTGy1a1G'] \
tags: ['attack.execution', 'attack.credential_access', 'attack.t1086'] \
author: John Lambert (idea), Florian Roth (rule) \
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
description = Detects PowerShell calling a credential prompt
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (EventID="4104" (Message="*PromptForCredential*")) | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_Credential_Prompt_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.credential_access,sigma_tag=attack.t1086,level=high"
```
