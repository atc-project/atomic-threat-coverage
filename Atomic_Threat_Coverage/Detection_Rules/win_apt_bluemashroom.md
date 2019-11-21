| Title                | BlueMashroom DLL Load                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1117: Regsvr32](../Triggers/T1117.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software](https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: BlueMashroom DLL Load
id: bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0
status: experimental
description: Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report
references:
    - https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software
tags:
    - attack.defense_evasion
    - attack.t1117
author: Florian Roth
date: 2019/10/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 
            - '*\regsvr32*\AppData\Local\\*'
            - '*\AppData\Local\\*,DllEntry*'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### splunk
    
```
(CommandLine="*\\\\regsvr32*\\\\AppData\\\\Local\\\\*" OR CommandLine="*\\\\AppData\\\\Local\\\\*,DllEntry*")
```



