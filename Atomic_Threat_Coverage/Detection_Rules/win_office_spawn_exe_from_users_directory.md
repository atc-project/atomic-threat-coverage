| Title                | MS Office Product Spawning Exe in User Dir                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c](sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c)</li><li>[https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign](https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign)</li></ul>  |
| Author               | Jason Lynch |
| Other Tags           | <ul><li>FIN7</li><li>FIN7</li><li>car.2013-05-002</li><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MS Office Product Spawning Exe in User Dir 
status: experimental
description: Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio
references:
    - sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c
    - https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign 
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1202
    - FIN7
    - car.2013-05-002
author: Jason Lynch 
date: 2019/04/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - 'C:\users\*.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\WINWORD.EXE *\\\\EXCEL.EXE *\\\\POWERPNT.exe *\\\\MSPUB.exe *\\\\VISIO.exe *\\\\OUTLOOK.EXE) AND Image:("C\\:\\\\users\\*.exe"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/MS-Office-Product-Spawning-Exe-in-User-Dir <<EOF\n{\n  "metadata": {\n    "title": "MS Office Product Spawning Exe in User Dir",\n    "description": "Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1059",\n      "attack.t1202",\n      "FIN7",\n      "car.2013-05-002"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\WINWORD.EXE *\\\\\\\\EXCEL.EXE *\\\\\\\\POWERPNT.exe *\\\\\\\\MSPUB.exe *\\\\\\\\VISIO.exe *\\\\\\\\OUTLOOK.EXE) AND Image:(\\"C\\\\:\\\\\\\\users\\\\*.exe\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\WINWORD.EXE *\\\\\\\\EXCEL.EXE *\\\\\\\\POWERPNT.exe *\\\\\\\\MSPUB.exe *\\\\\\\\VISIO.exe *\\\\\\\\OUTLOOK.EXE) AND Image:(\\"C\\\\:\\\\\\\\users\\\\*.exe\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MS Office Product Spawning Exe in User Dir\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\WINWORD.EXE" "*\\\\EXCEL.EXE" "*\\\\POWERPNT.exe" "*\\\\MSPUB.exe" "*\\\\VISIO.exe" "*\\\\OUTLOOK.EXE") AND Image:("C\\:\\\\users\\*.exe"))
```


### splunk
    
```
((ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE" OR ParentImage="*\\\\POWERPNT.exe" OR ParentImage="*\\\\MSPUB.exe" OR ParentImage="*\\\\VISIO.exe" OR ParentImage="*\\\\OUTLOOK.EXE") (Image="C:\\\\users\\*.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(ParentImage IN ["*\\\\WINWORD.EXE", "*\\\\EXCEL.EXE", "*\\\\POWERPNT.exe", "*\\\\MSPUB.exe", "*\\\\VISIO.exe", "*\\\\OUTLOOK.EXE"] Image IN ["C:\\\\users\\*.exe"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\WINWORD\\.EXE|.*.*\\EXCEL\\.EXE|.*.*\\POWERPNT\\.exe|.*.*\\MSPUB\\.exe|.*.*\\VISIO\\.exe|.*.*\\OUTLOOK\\.EXE))(?=.*(?:.*C:\\users\\.*\\.exe)))'
```



