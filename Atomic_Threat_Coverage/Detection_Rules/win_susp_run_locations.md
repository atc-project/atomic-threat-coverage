| Title                | Suspicious Process Start Locations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process run from unusual locations                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-05-002](https://car.mitre.org/wiki/CAR-2013-05-002)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Process Start Locations
id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*:\RECYCLER\\*'
            - '*:\SystemVolumeInformation\\*'
            - 'C:\\Windows\\Tasks\\*'
            - 'C:\\Windows\\debug\\*'
            - 'C:\\Windows\\fonts\\*'
            - 'C:\\Windows\\help\\*'
            - 'C:\\Windows\\drivers\\*'
            - 'C:\\Windows\\addins\\*'
            - 'C:\\Windows\\cursors\\*'
            - 'C:\\Windows\\system32\tasks\\*'
            
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(Image="*:\\\\RECYCLER\\\\*" OR Image="*:\\\\SystemVolumeInformation\\\\*" OR Image="C:\\\\Windows\\\\Tasks\\\\*" OR Image="C:\\\\Windows\\\\debug\\\\*" OR Image="C:\\\\Windows\\\\fonts\\\\*" OR Image="C:\\\\Windows\\\\help\\\\*" OR Image="C:\\\\Windows\\\\drivers\\\\*" OR Image="C:\\\\Windows\\\\addins\\\\*" OR Image="C:\\\\Windows\\\\cursors\\\\*" OR Image="C:\\\\Windows\\\\system32\\\\tasks\\\\*")
```



