| Title                | Sticky Key Like Backdoor Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1015: Accessibility Features](https://attack.mitre.org/techniques/T1015)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1015: Accessibility Features](../Triggers/T1015.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unlikely</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/](https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/)</li></ul>                                                          |
| Author               | Florian Roth, @twjackomo                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Sticky Key Like Backdoor Usage
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1015
author: Florian Roth, @twjackomo
date: 2018/03/15
detection:
    condition: 1 of them
falsepositives:
    - Unlikely
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger'
        EventType: 'SetValue'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        ParentImage:
            - '*\winlogon.exe'
        CommandLine:
            - '*cmd.exe sethc.exe *'
            - '*cmd.exe utilman.exe *'
            - '*cmd.exe osk.exe *'
            - '*cmd.exe Magnify.exe *'
            - '*cmd.exe Narrator.exe *'
            - '*cmd.exe DisplaySwitch.exe *'

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\osk.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Magnify.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Narrator.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\DisplaySwitch.exe\\\\Debugger") AND EventType:"SetValue")\n(ParentImage:("*\\\\winlogon.exe") AND CommandLine:("*cmd.exe sethc.exe *" "*cmd.exe utilman.exe *" "*cmd.exe osk.exe *" "*cmd.exe Magnify.exe *" "*cmd.exe Narrator.exe *" "*cmd.exe DisplaySwitch.exe *"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch\\.exe\\Debugger))(?=.*SetValue))'\ngrep -P '^(?:.*(?=.*(?:.*.*\\winlogon\\.exe))(?=.*(?:.*.*cmd\\.exe sethc\\.exe .*|.*.*cmd\\.exe utilman\\.exe .*|.*.*cmd\\.exe osk\\.exe .*|.*.*cmd\\.exe Magnify\\.exe .*|.*.*cmd\\.exe Narrator\\.exe .*|.*.*cmd\\.exe DisplaySwitch\\.exe .*)))'
```



