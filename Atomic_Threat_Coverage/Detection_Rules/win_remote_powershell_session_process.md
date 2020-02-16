| Title                | T1086 Remote PowerShell Session                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote PowerShell seccions by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote sessionn)                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1086 Remote PowerShell Session
id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8
description: Detects remote PowerShell seccions by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote sessionn)
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\wsmprovhost.exe'
        - ParentImage|endswith: '\wsmprovhost.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(Image.keyword:*\\\\wsmprovhost.exe OR ParentImage.keyword:*\\\\wsmprovhost.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1086-Remote-PowerShell-Session <<EOF\n{\n  "metadata": {\n    "title": "T1086 Remote PowerShell Session",\n    "description": "Detects remote PowerShell seccions by monitoring for wsmprovhost as a parent or child process (sign of an active ps remote sessionn)",\n    "tags": "",\n    "query": "(Image.keyword:*\\\\\\\\wsmprovhost.exe OR ParentImage.keyword:*\\\\\\\\wsmprovhost.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\wsmprovhost.exe OR ParentImage.keyword:*\\\\\\\\wsmprovhost.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1086 Remote PowerShell Session\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\wsmprovhost.exe OR ParentImage.keyword:*\\\\wsmprovhost.exe)
```


### splunk
    
```
(Image="*\\\\wsmprovhost.exe" OR ParentImage="*\\\\wsmprovhost.exe")
```


### logpoint
    
```
(event_id="1" (Image="*\\\\wsmprovhost.exe" OR ParentImage="*\\\\wsmprovhost.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\wsmprovhost\\.exe|.*.*\\wsmprovhost\\.exe))'
```



