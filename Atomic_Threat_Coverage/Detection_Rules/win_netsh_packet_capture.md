| Title                | Capture a Network Trace with netsh.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects capture a network trace via netsh.exe trace functionality                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)</li></ul>  |
| Author               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Capture a Network Trace with netsh.exe
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: experimental
description: Detects capture a network trace via netsh.exe trace functionality
references:
    - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
author: Kutepov Anton, oscd.community
date: 2019/10/24
tags:
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - netsh
            - trace
            - start
    condition: selection    
falsepositives: 
    - Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason
level: medium

```





### splunk
    
```
(CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```



