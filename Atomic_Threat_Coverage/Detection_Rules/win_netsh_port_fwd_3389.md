| Title                | Netsh RDP Port Forwarding                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects netsh commands that configure a port forwarding of port 3389 used for RDP                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1021: Remote Services](../Triggers/T1021.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Netsh RDP Port Forwarding
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1021
    - car.2013-07-002
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh i* p*=3389 c*
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```





### splunk
    
```
(CommandLine="netsh i* p*=3389 c*")
```



