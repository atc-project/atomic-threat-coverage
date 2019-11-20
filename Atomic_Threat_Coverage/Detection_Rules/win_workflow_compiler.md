| Title                | Microsoft Workflow Compiler                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate MWC use (unlikely in modern enterprise environments)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)</li></ul>  |
| Author               | Nik Seetharaman |


## Detection Rules

### Sigma rule

```
title: Microsoft Workflow Compiler
id: 419dbf2b-8a9b-4bea-bf99-7544b050ec8d
status: experimental
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1127
author: Nik Seetharaman
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: high

```





### splunk
    
```
Image="*\\\\Microsoft.Workflow.Compiler.exe" | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Microsoft Workflow Compiler]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Microsoft Workflow Compiler status: experimental \
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code. \
references: ['https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1127'] \
author: Nik Seetharaman \
date:  \
falsepositives: ['Legitimate MWC use (unlikely in modern enterprise environments)'] \
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
description = Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = Image="*\\Microsoft.Workflow.Compiler.exe" | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Microsoft_Workflow_Compiler_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1127,level=high"
```
