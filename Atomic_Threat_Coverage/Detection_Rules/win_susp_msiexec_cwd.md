| Title                | Suspicious MsiExec Directory                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious msiexec process starts in an uncommon directory                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/200_okay_/status/1194765831911215104](https://twitter.com/200_okay_/status/1194765831911215104)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious MsiExec Directory
id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: experimental
description: Detects suspicious msiexec process starts in an uncommon directory
references:
    - https://twitter.com/200_okay_/status/1194765831911215104
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/11/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\msiexec.exe'
    filter:
        Image: 
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
            - 'C:\Windows\WinSxS\\*' 
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```





### splunk
    
```
(Image="*\\\\msiexec.exe" NOT ((Image="C:\\\\Windows\\\\System32\\\\*" OR Image="C:\\\\Windows\\\\SysWOW64\\\\*" OR Image="C:\\\\Windows\\\\WinSxS\\\\*")))
```



