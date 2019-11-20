| Title                | PowerShell Download from URL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Powershell process that contains download commands in its command line string                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Download from URL
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth
tags:
    - attack.t1086
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### splunk
    
```
(Image="*\\\\powershell.exe" (CommandLine="*new-object system.net.webclient).downloadstring(*" OR CommandLine="*new-object system.net.webclient).downloadfile(*" OR CommandLine="*new-object net.webclient).downloadstring(*" OR CommandLine="*new-object net.webclient).downloadfile(*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[PowerShell Download from URL]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: PowerShell Download from URL status: experimental \
description: Detects a Powershell process that contains download commands in its command line string \
references:  \
tags: ['attack.t1086', 'attack.execution'] \
author: Florian Roth \
date:  \
falsepositives: ['unknown'] \
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
description = Detects a Powershell process that contains download commands in its command line string
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\powershell.exe" (CommandLine="*new-object system.net.webclient).downloadstring(*" OR CommandLine="*new-object system.net.webclient).downloadfile(*" OR CommandLine="*new-object net.webclient).downloadstring(*" OR CommandLine="*new-object net.webclient).downloadfile(*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup PowerShell_Download_from_URL_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.t1086,sigma_tag=attack.execution,level=medium"
```
