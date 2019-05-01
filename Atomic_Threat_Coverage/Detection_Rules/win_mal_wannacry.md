| Title                | WannaCry Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WannaCry Ransomware Activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WannaCry Ransomware
description: Detects WannaCry Ransomware Activity
status: experimental
references:
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*vssadmin delete shadows*'
            - '*icacls * /grant Everyone:F /T /C /Q*'
            - '*bcdedit /set {default} recoveryenabled no*'
            - '*wbadmin delete catalog -quiet*'
    selection2:
        Image:
            - '*\tasksche.exe'
            - '*\mssecsvc.exe'
            - '*\taskdl.exe'
            - '*\WanaDecryptor*'
            - '*\taskhsvc.exe'
            - '*\taskse.exe'
            - '*\111.exe'
            - '*\lhdfrgui.exe'
            - '*\diskpart.exe'
            - '*\linuxnew.exe'
            - '*\wannacry.exe'
    condition: 1 of them
falsepositives:
    - Unknown
level: critical

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR Image:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*vssadmin delete shadows.*|.*.*icacls .* /grant Everyone:F /T /C /Q.*|.*.*bcdedit /set \\{default\\} recoveryenabled no.*|.*.*wbadmin delete catalog -quiet.*)|.*(?:.*.*\\tasksche\\.exe|.*.*\\mssecsvc\\.exe|.*.*\\taskdl\\.exe|.*.*\\WanaDecryptor.*|.*.*\\taskhsvc\\.exe|.*.*\\taskse\\.exe|.*.*\\111\\.exe|.*.*\\lhdfrgui\\.exe|.*.*\\diskpart\\.exe|.*.*\\linuxnew\\.exe|.*.*\\wannacry\\.exe)))'
```



