| Title                | Firewall Disabled via Netsh                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects netsh commands that turns off the Windows firewall                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate administration</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.winhelponline.com/blog/enable-and-disable-windows-firewall-quickly-using-command-line/](https://www.winhelponline.com/blog/enable-and-disable-windows-firewall-quickly-using-command-line/)</li><li>[https://app.any.run/tasks/210244b9-0b6b-4a2c-83a3-04bd3175d017/](https://app.any.run/tasks/210244b9-0b6b-4a2c-83a3-04bd3175d017/)</li></ul>  |
| Author               | Fatih Sirin |


## Detection Rules

### Sigma rule

```
title: Firewall Disabled via Netsh
id: 57c4bf16-227f-4394-8ec7-1b745ee061c3
description: Detects netsh commands that turns off the Windows firewall
references:
    - https://www.winhelponline.com/blog/enable-and-disable-windows-firewall-quickly-using-command-line/
    - https://app.any.run/tasks/210244b9-0b6b-4a2c-83a3-04bd3175d017/
date: 2019/11/01
status: experimental
author: Fatih Sirin
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh firewall set opmode mode=disable
            - netsh advfirewall set * state off
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```





### splunk
    
```
(CommandLine="netsh firewall set opmode mode=disable" OR CommandLine="netsh advfirewall set * state off")
```



