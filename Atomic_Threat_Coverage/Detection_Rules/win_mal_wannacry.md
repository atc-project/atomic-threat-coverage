| Title                | WannaCry Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WannaCry Ransomware Activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
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
(CommandLine.keyword:(*vssadmin\\ delete\\ shadows* *icacls\\ *\\ \\/grant\\ Everyone\\:F\\ \\/T\\ \\/C\\ \\/Q* *bcdedit\\ \\/set\\ \\{default\\}\\ recoveryenabled\\ no* *wbadmin\\ delete\\ catalog\\ \\-quiet*) OR Image.keyword:(*\\\\tasksche.exe *\\\\mssecsvc.exe *\\\\taskdl.exe *\\\\WanaDecryptor* *\\\\taskhsvc.exe *\\\\taskse.exe *\\\\111.exe *\\\\lhdfrgui.exe *\\\\diskpart.exe *\\\\linuxnew.exe *\\\\wannacry.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WannaCry-Ransomware <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(CommandLine.keyword:(*vssadmin\\\\ delete\\\\ shadows* *icacls\\\\ *\\\\ \\\\/grant\\\\ Everyone\\\\:F\\\\ \\\\/T\\\\ \\\\/C\\\\ \\\\/Q* *bcdedit\\\\ \\\\/set\\\\ \\\\{default\\\\}\\\\ recoveryenabled\\\\ no* *wbadmin\\\\ delete\\\\ catalog\\\\ \\\\-quiet*) OR Image.keyword:(*\\\\\\\\tasksche.exe *\\\\\\\\mssecsvc.exe *\\\\\\\\taskdl.exe *\\\\\\\\WanaDecryptor* *\\\\\\\\taskhsvc.exe *\\\\\\\\taskse.exe *\\\\\\\\111.exe *\\\\\\\\lhdfrgui.exe *\\\\\\\\diskpart.exe *\\\\\\\\linuxnew.exe *\\\\\\\\wannacry.exe))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WannaCry Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR Image:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe"))
```


### splunk
    
```
((CommandLine="*vssadmin delete shadows*" OR CommandLine="*icacls * /grant Everyone:F /T /C /Q*" OR CommandLine="*bcdedit /set {default} recoveryenabled no*" OR CommandLine="*wbadmin delete catalog -quiet*") OR (Image="*\\\\tasksche.exe" OR Image="*\\\\mssecsvc.exe" OR Image="*\\\\taskdl.exe" OR Image="*\\\\WanaDecryptor*" OR Image="*\\\\taskhsvc.exe" OR Image="*\\\\taskse.exe" OR Image="*\\\\111.exe" OR Image="*\\\\lhdfrgui.exe" OR Image="*\\\\diskpart.exe" OR Image="*\\\\linuxnew.exe" OR Image="*\\\\wannacry.exe"))
```


### logpoint
    
```
(CommandLine IN ["*vssadmin delete shadows*", "*icacls * /grant Everyone:F /T /C /Q*", "*bcdedit /set {default} recoveryenabled no*", "*wbadmin delete catalog -quiet*"] OR Image IN ["*\\\\tasksche.exe", "*\\\\mssecsvc.exe", "*\\\\taskdl.exe", "*\\\\WanaDecryptor*", "*\\\\taskhsvc.exe", "*\\\\taskse.exe", "*\\\\111.exe", "*\\\\lhdfrgui.exe", "*\\\\diskpart.exe", "*\\\\linuxnew.exe", "*\\\\wannacry.exe"])
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*vssadmin delete shadows.*|.*.*icacls .* /grant Everyone:F /T /C /Q.*|.*.*bcdedit /set \\{default\\} recoveryenabled no.*|.*.*wbadmin delete catalog -quiet.*)|.*(?:.*.*\\tasksche\\.exe|.*.*\\mssecsvc\\.exe|.*.*\\taskdl\\.exe|.*.*\\WanaDecryptor.*|.*.*\\taskhsvc\\.exe|.*.*\\taskse\\.exe|.*.*\\111\\.exe|.*.*\\lhdfrgui\\.exe|.*.*\\diskpart\\.exe|.*.*\\linuxnew\\.exe|.*.*\\wannacry\\.exe)))'
```



