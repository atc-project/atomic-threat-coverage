| Title                | Suspicious Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process starts with base64 encoded commands                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>  |
| Author               | Florian Roth, Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
description: Detects suspicious powershell process starts with base64 encoded commands
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
modified: 2019/07/30
tags:
  - attack.execution
  - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -e  JAB*'
            - '* -e   JAB*'
            - '* -e    JAB*'
            - '* -e     JAB*'
            - '* -e      JAB*'
            - '* -enc JAB*'
            - '* -enco JAB*'
            - '* -encodedcommand JAB*'
            - '* BA^J e-'
            - '* -e SUVYI*'
            - '* -e aWV4I*'
            - '* -e SQBFAFgA*'
            - '* -e aQBlAHgA*'
            - '* -enc SUVYI*'
            - '* -enc aWV4I*'
            - '* -enc SQBFAFgA*'
            - '* -enc aQBlAHgA*'
    falsepositive1:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not falsepositive1
level: high

```





### splunk
    
```
((CommandLine="* -e JAB*" OR CommandLine="* -e  JAB*" OR CommandLine="* -e   JAB*" OR CommandLine="* -e    JAB*" OR CommandLine="* -e     JAB*" OR CommandLine="* -e      JAB*" OR CommandLine="* -enc JAB*" OR CommandLine="* -enco JAB*" OR CommandLine="* -encodedcommand JAB*" OR CommandLine="* BA^J e-" OR CommandLine="* -e SUVYI*" OR CommandLine="* -e aWV4I*" OR CommandLine="* -e SQBFAFgA*" OR CommandLine="* -e aQBlAHgA*" OR CommandLine="* -enc SUVYI*" OR CommandLine="* -enc aWV4I*" OR CommandLine="* -enc SQBFAFgA*" OR CommandLine="* -enc aQBlAHgA*") NOT (CommandLine="* -ExecutionPolicy remotesigned *"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious Encoded PowerShell Command Line]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious Encoded PowerShell Command Line status: experimental \
description: Detects suspicious powershell process starts with base64 encoded commands \
references: ['https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth, Markus Neis \
date:  \
falsepositives:  \
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
description = Detects suspicious powershell process starts with base64 encoded commands
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((CommandLine="* -e JAB*" OR CommandLine="* -e  JAB*" OR CommandLine="* -e   JAB*" OR CommandLine="* -e    JAB*" OR CommandLine="* -e     JAB*" OR CommandLine="* -e      JAB*" OR CommandLine="* -enc JAB*" OR CommandLine="* -enco JAB*" OR CommandLine="* -encodedcommand JAB*" OR CommandLine="* BA^J e-" OR CommandLine="* -e SUVYI*" OR CommandLine="* -e aWV4I*" OR CommandLine="* -e SQBFAFgA*" OR CommandLine="* -e aQBlAHgA*" OR CommandLine="* -enc SUVYI*" OR CommandLine="* -enc aWV4I*" OR CommandLine="* -enc SQBFAFgA*" OR CommandLine="* -enc aQBlAHgA*") NOT (CommandLine="* -ExecutionPolicy remotesigned *")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_Encoded_PowerShell_Command_Line_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
