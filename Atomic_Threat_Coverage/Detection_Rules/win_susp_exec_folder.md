| Title                | Executables Started in Suspicious Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process starts of binaries from a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt](https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt)</li><li>[https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses](https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses)</li><li>[https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/](https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Executables Started in Suspicious Folder
id: 7a38aa19-86a9-4af7-ac51-6bfe4e59f254
status: experimental
description: Detects process starts of binaries from a suspicious folder
author: Florian Roth
date: 2017/10/14
modified: 2019/02/21
references:
    - https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt
    - https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - C:\PerfLogs\\*
            - C:\$Recycle.bin\\*
            - C:\Intel\Logs\\*
            - C:\Users\Default\\*
            - C:\Users\Public\\*
            - C:\Users\NetworkService\\*
            - C:\Windows\Fonts\\*
            - C:\Windows\Debug\\*
            - C:\Windows\Media\\*
            - C:\Windows\Help\\*
            - C:\Windows\addins\\*
            - C:\Windows\repair\\*
            - C:\Windows\security\\*
            - '*\RSA\MachineKeys\\*'
            - C:\Windows\system32\config\systemprofile\\*
    condition: selection
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(Image="C:\\\\PerfLogs\\\\*" OR Image="C:\\\\$Recycle.bin\\\\*" OR Image="C:\\\\Intel\\\\Logs\\\\*" OR Image="C:\\\\Users\\\\Default\\\\*" OR Image="C:\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Users\\\\NetworkService\\\\*" OR Image="C:\\\\Windows\\\\Fonts\\\\*" OR Image="C:\\\\Windows\\\\Debug\\\\*" OR Image="C:\\\\Windows\\\\Media\\\\*" OR Image="C:\\\\Windows\\\\Help\\\\*" OR Image="C:\\\\Windows\\\\addins\\\\*" OR Image="C:\\\\Windows\\\\repair\\\\*" OR Image="C:\\\\Windows\\\\security\\\\*" OR Image="*\\\\RSA\\\\MachineKeys\\\\*" OR Image="C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\\\*")
```



