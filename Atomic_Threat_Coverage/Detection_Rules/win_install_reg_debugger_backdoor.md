| Title                | Suspicious Debugger Registration Cmdline                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1015: Accessibility Features](https://attack.mitre.org/techniques/T1015)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1015: Accessibility Features](../Triggers/T1015.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration Tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/](https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Debugger Registration Cmdline
id: ae215552-081e-44c7-805f-be16f975c8a2
status: experimental
description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1015
author: Florian Roth
date: 2019/09/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\CurrentVersion\Image File Execution Options\sethc.exe*'
            - '*\CurrentVersion\Image File Execution Options\utilman.exe*'
            - '*\CurrentVersion\Image File Execution Options\osk.exe*'
            - '*\CurrentVersion\Image File Execution Options\magnify.exe*'
            - '*\CurrentVersion\Image File Execution Options\narrator.exe*'
            - '*\CurrentVersion\Image File Execution Options\displayswitch.exe*'
    condition: selection
falsepositives:
    - Penetration Tests
level: high
        

```





### splunk
    
```
(CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe*" OR CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe*" OR CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\osk.exe*" OR CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\magnify.exe*" OR CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\narrator.exe*" OR CommandLine="*\\\\CurrentVersion\\\\Image File Execution Options\\\\displayswitch.exe*")
```



