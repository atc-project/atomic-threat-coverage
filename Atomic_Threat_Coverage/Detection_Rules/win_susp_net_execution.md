| Title                | Net.exe Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of Net.exe, whether suspicious or benign.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | low |
| False Positives      | <ul><li>Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)</li></ul>  |
| Author               | Michael Haag, Mark Woan (improvements) |
| Other Tags           | <ul><li>attack.s0039</li><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Net.exe Execution
id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac
status: experimental
description: Detects execution of Net.exe, whether suspicious or benign.
references:
    - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
author: Michael Haag, Mark Woan (improvements)
tags:
    - attack.s0039
    - attack.lateral_movement
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\net.exe'
            - '*\net1.exe'
        CommandLine:
            - '* group*'
            - '* localgroup*'
            - '* user*'
            - '* view*'
            - '* share'
            - '* accounts*'
            - '* use*'
            - '* stop *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.
level: low

```





### splunk
    
```
((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") (CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="* user*" OR CommandLine="* view*" OR CommandLine="* share" OR CommandLine="* accounts*" OR CommandLine="* use*" OR CommandLine="* stop *")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Net.exe Execution]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Net.exe Execution status: experimental \
description: Detects execution of Net.exe, whether suspicious or benign. \
references: ['https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/'] \
tags: ['attack.s0039', 'attack.lateral_movement', 'attack.discovery'] \
author: Michael Haag, Mark Woan (improvements) \
date:  \
falsepositives: ['Will need to be tuned. If using Splunk, I recommend \
 stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects execution of Net.exe, whether suspicious or benign.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\net.exe" OR Image="*\\net1.exe") (CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="* user*" OR CommandLine="* view*" OR CommandLine="* share" OR CommandLine="* accounts*" OR CommandLine="* use*" OR CommandLine="* stop *")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Net.exe_Execution_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.s0039,sigma_tag=attack.lateral_movement,sigma_tag=attack.discovery,level=low"
```
