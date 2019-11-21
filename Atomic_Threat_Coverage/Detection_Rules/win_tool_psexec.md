| Title                | PsExec Tool Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects PsExec service installation and execution events (service and Sysmon)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0031_7036_service_started_stopped](../Data_Needed/DN_0031_7036_service_started_stopped.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: PsExec Tool Execution
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: experimental
description: Detects PsExec service installation and execution events (service and Sysmon)
author: Thomas Patzke
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.execution
    - attack.t1035
    - attack.s0029
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - ServiceName
    - ServiceFileName
falsepositives:
    - unknown
level: low
---
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'PSEXESVC'
        ServiceFileName: '*\PSEXESVC.exe'
    service_execution:
        EventID: 7036
        ServiceName: 'PSEXESVC'
---
logsource:
    category: process_creation
    product: windows
detection:
    sysmon_processcreation:
        Image: '*\PSEXESVC.exe'
        User: 'NT AUTHORITY\SYSTEM'


```





### splunk
    
```
(ServiceName="PSEXESVC" ((EventID="7045" ServiceFileName="*\\\\PSEXESVC.exe") OR EventID="7036")) | table EventID,CommandLine,ParentCommandLine,ServiceName,ServiceFileName\n(Image="*\\\\PSEXESVC.exe" User="NT AUTHORITY\\\\SYSTEM") | table EventID,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
```



