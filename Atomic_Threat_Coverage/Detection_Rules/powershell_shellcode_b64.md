| Title                | PowerShell ShellCode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Base64 encoded Shellcode                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>  |
| Author               | David Ledbetter (shellcode), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell ShellCode
id: 16b37b70-6fcf-4814-a092-c36bd3aafcbd
status: experimental
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
tags:
    - attack.privilege_escalation
    - attack.execution
    - attack.t1055
    - attack.t1086
author: David Ledbetter (shellcode), Florian Roth (rule)
date: 2018/11/17
logsource:
    product: windows
    service: powershell
    description: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1: 
        - '*AAAAYInlM*'
    keyword2: 
        - '*OiCAAAAYInlM*'
        - '*OiJAAAAYInlM*'
    condition: selection and keyword1 and keyword2
falsepositives:
    - Unknown
level: critical

```





### splunk
    
```
((EventID="4104" "*AAAAYInlM*") ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell ShellCode]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: PowerShell ShellCode status: experimental \
description: Detects Base64 encoded Shellcode \
references: ['https://twitter.com/cyb3rops/status/1063072865992523776'] \
tags: ['attack.privilege_escalation', 'attack.execution', 'attack.t1055', 'attack.t1086'] \
author: David Ledbetter (shellcode), Florian Roth (rule) \
date:  \
falsepositives: ['Unknown'] \
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
description = Detects Base64 encoded Shellcode
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((EventID="4104" "*AAAAYInlM*") ("*OiCAAAAYInlM*" OR "*OiJAAAAYInlM*")) | stats values(*) AS * by _time | search NOT [| inputlookup PowerShell_ShellCode_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.execution,sigma_tag=attack.t1055,sigma_tag=attack.t1086,level=critical"
```
