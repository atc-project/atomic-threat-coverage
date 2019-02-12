| Title                | WannaCry Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WannaCry Ransomware Activity                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
action: global
title: WannaCry Ransomware 
description: Detects WannaCry Ransomware Activity
status: experimental
references:
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
author: Florian Roth
detection:
    selection1:
        CommandLine:
            - '*vssadmin delete shadows*'
            - '*icacls * /grant Everyone:F /T /C /Q*'
            - '*bcdedit /set {default} recoveryenabled no*'
            - '*wbadmin delete catalog -quiet*'
    condition: 1 of them
falsepositives: 
    - Unknown
level: critical
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection1:
        # Requires group policy 'Audit Process Creation' > Include command line in process creation events
        EventID: 4688
    selection2:
        # Does not require group policy 'Audit Process Creation' > Include command line in process creation events
        EventID: 4688
        NewProcessName:
            - '*\tasksche.exe'
            - '*\mssecsvc.exe'
            - '*\taskdl.exe'
            - '*\WanaDecryptor*'
            - '*\taskhsvc.exe'
            - '*\taskse.exe'
            - '*\111.exe'
            - '*\lhdfrgui.exe'
            - '*\diskpart.exe'  # Rare, but can be false positive
            - '*\linuxnew.exe'
            - '*\wannacry.exe'
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        # Requires group policy 'Audit Process Creation' > Include command line in process creation events
        EventID: 1
    selection2:
        # Does not require group policy 'Audit Process Creation' > Include command line in process creation events
        EventID: 1
        Image:
            - '*\tasksche.exe'
            - '*\mssecsvc.exe'
            - '*\taskdl.exe'
            - '*\WanaDecryptor*'
            - '*\taskhsvc.exe'
            - '*\taskse.exe'
            - '*\111.exe'
            - '*\lhdfrgui.exe'
            - '*\diskpart.exe'  # Rare, but can be false positive
            - '*\linuxnew.exe'
            - '*\wannacry.exe'

```





### Kibana query

```
(EventID:"4688" AND (CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR NewProcessName:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe")))\n(EventID:"1" AND (CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR Image:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe")))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WannaCry-Ransomware <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND (CommandLine:(\\"*vssadmin delete shadows*\\" \\"*icacls * \\\\/grant Everyone\\\\:F \\\\/T \\\\/C \\\\/Q*\\" \\"*bcdedit \\\\/set \\\\{default\\\\} recoveryenabled no*\\" \\"*wbadmin delete catalog \\\\-quiet*\\") OR NewProcessName:(\\"*\\\\\\\\tasksche.exe\\" \\"*\\\\\\\\mssecsvc.exe\\" \\"*\\\\\\\\taskdl.exe\\" \\"*\\\\\\\\WanaDecryptor*\\" \\"*\\\\\\\\taskhsvc.exe\\" \\"*\\\\\\\\taskse.exe\\" \\"*\\\\\\\\111.exe\\" \\"*\\\\\\\\lhdfrgui.exe\\" \\"*\\\\\\\\diskpart.exe\\" \\"*\\\\\\\\linuxnew.exe\\" \\"*\\\\\\\\wannacry.exe\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WannaCry Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WannaCry-Ransomware-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND (CommandLine:(\\"*vssadmin delete shadows*\\" \\"*icacls * \\\\/grant Everyone\\\\:F \\\\/T \\\\/C \\\\/Q*\\" \\"*bcdedit \\\\/set \\\\{default\\\\} recoveryenabled no*\\" \\"*wbadmin delete catalog \\\\-quiet*\\") OR Image:(\\"*\\\\\\\\tasksche.exe\\" \\"*\\\\\\\\mssecsvc.exe\\" \\"*\\\\\\\\taskdl.exe\\" \\"*\\\\\\\\WanaDecryptor*\\" \\"*\\\\\\\\taskhsvc.exe\\" \\"*\\\\\\\\taskse.exe\\" \\"*\\\\\\\\111.exe\\" \\"*\\\\\\\\lhdfrgui.exe\\" \\"*\\\\\\\\diskpart.exe\\" \\"*\\\\\\\\linuxnew.exe\\" \\"*\\\\\\\\wannacry.exe\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WannaCry Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4688" AND (CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR NewProcessName:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe")))\n(EventID:"1" AND (CommandLine:("*vssadmin delete shadows*" "*icacls * \\/grant Everyone\\:F \\/T \\/C \\/Q*" "*bcdedit \\/set \\{default\\} recoveryenabled no*" "*wbadmin delete catalog \\-quiet*") OR Image:("*\\\\tasksche.exe" "*\\\\mssecsvc.exe" "*\\\\taskdl.exe" "*\\\\WanaDecryptor*" "*\\\\taskhsvc.exe" "*\\\\taskse.exe" "*\\\\111.exe" "*\\\\lhdfrgui.exe" "*\\\\diskpart.exe" "*\\\\linuxnew.exe" "*\\\\wannacry.exe")))
```

