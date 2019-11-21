| Title                | Java Running with Remote Debugging                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a JAVA process running with remote debugging allowing more than just localhost to connect                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1046: Network Service Scanning](../Triggers/T1046.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Java Running with Remote Debugging
id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
author: Florian Roth
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*transport=dt_socket,address=*'
    exclusion:
        - CommandLine: '*address=127.0.0.1*'
        - CommandLine: '*address=localhost*'
    condition: selection and not exclusion
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```





### splunk
    
```
(CommandLine="*transport=dt_socket,address=*" NOT (CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*")) | table CommandLine,ParentCommandLine
```



