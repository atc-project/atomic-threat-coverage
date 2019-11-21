| Title                | Microsoft Workflow Compiler                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
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



