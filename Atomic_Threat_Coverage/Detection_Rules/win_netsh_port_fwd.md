| Title                | Netsh Port Forwarding                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects netsh commands that configure a port forwarding                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1090: Connection Proxy](https://attack.mitre.org/techniques/T1090)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1090: Connection Proxy](../Triggers/T1090.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Netsh Port Forwarding
id: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
description: Detects netsh commands that configure a port forwarding
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh interface portproxy add v4tov4 *
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```





### splunk
    
```
(CommandLine="netsh interface portproxy add v4tov4 *")
```



