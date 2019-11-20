| Title                | Suspicious PowerShell Invocations - Generic                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation command parameters                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li><li>Very special / sneaky PowerShell scripts</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Generic
id: 3d304fda-78aa-43ed-975c-d740798a49c1
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
    encoded:
        - ' -enc '
        - ' -EncodedCommand '
    hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' - windowstyle hidden '
    noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of them
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
level: high


```





### splunk
    
```
((" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " - windowstyle hidden ") (" -noni " OR " -noninteractive "))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Invocations - Generic]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PowerShell Invocations - Generic status: experimental \
description: Detects suspicious PowerShell invocation command parameters \
references:  \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth (rule) \
date:  \
falsepositives: ['Penetration tests', 'Very special / sneaky PowerShell scripts'] \
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
search = ((" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " - windowstyle hidden ") (" -noni " OR " -noninteractive ")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PowerShell_Invocations_-_Generic_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
