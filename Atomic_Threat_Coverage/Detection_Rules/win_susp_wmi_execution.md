| Title                | Suspicious WMI execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI executing suspicious commands                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Will need to be tuned</li><li>If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/](https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/)</li><li>[https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1](https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1)</li><li>[https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/](https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/)</li></ul>  |
| Author               | Michael Haag, Florian Roth, juju4 |
| Other Tags           | <ul><li>car.2016-03-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious WMI execution
id: 526be59f-a573-4eea-b5f7-f0973207634d
status: experimental
description: Detects WMI executing suspicious commands
references:
    - https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/
    - https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1
    - https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/
author: Michael Haag, Florian Roth, juju4
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - '*/NODE:*process call create *'
            - '* path AntiVirusProduct get *'
            - '* path FirewallProduct get *'
            - '* shadowcopy delete *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
    - car.2016-03-002
falsepositives:
    - Will need to be tuned
    - If using Splunk, I recommend | stats count by Computer,CommandLine following for easy hunting by Computer/CommandLine.
level: medium

```





### splunk
    
```
((Image="*\\\\wmic.exe") (CommandLine="*/NODE:*process call create *" OR CommandLine="* path AntiVirusProduct get *" OR CommandLine="* path FirewallProduct get *" OR CommandLine="* shadowcopy delete *")) | table CommandLine,ParentCommandLine
```



