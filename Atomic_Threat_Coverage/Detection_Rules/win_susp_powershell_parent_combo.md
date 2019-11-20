| Title                | Suspicious PowerShell Invocation based on Parent Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell invocations from interpreters or unusual programs                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Microsoft Operations Manager (MOM)</li><li>Other scripts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/](https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocation based on Parent Process
id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: experimental
description: Detects suspicious powershell invocations from interpreters or unusual programs
author: Florian Roth
references:
    - https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
tags:
    - attack.execution
    - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
        Image:
            - '*\powershell.exe'
    falsepositive:
        CurrentDirectory: '*\Health Service State\\*'
    condition: selection and not falsepositive
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium

```





### splunk
    
```
(((ParentImage="*\\\\wscript.exe" OR ParentImage="*\\\\cscript.exe") (Image="*\\\\powershell.exe")) NOT (CurrentDirectory="*\\\\Health Service State\\\\*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Invocation based on Parent Process]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Suspicious PowerShell Invocation based on Parent Process status: experimental \
description: Detects suspicious powershell invocations from interpreters or unusual programs \
references: ['https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth \
date:  \
falsepositives: ['Microsoft Operations Manager (MOM)', 'Other scripts'] \
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
description = Detects suspicious powershell invocations from interpreters or unusual programs
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (((ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe") (Image="*\\powershell.exe")) NOT (CurrentDirectory="*\\Health Service State\\*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Suspicious_PowerShell_Invocation_based_on_Parent_Process_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=medium"
```
