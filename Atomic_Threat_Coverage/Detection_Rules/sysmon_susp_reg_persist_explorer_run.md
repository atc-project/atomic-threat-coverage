| Title                | Registry Persistence via Explorer Run Key                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible persistence mechanism using RUN key for Windows Explorer and poiting to a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/](https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>capec.270</li><li>capec.270</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Registry Persistence via Explorer Run Key
status: experimental
description: Detects a possible persistence mechanism using RUN key for Windows Explorer and poiting to a suspicious folder
author: Florian Roth
date: 2018/07/18
references:
    - https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Details: 
            - 'C:\Windows\Temp\\*'
            - 'C:\ProgramData\\*'
            - '*\AppData\\*'
            - 'C:\$Recycle.bin\\*'
            - 'C:\Temp\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
    condition: selection
tags:
    - attack.persistence
    - attack.t1060
    - capec.270
fields:
    - Image
    - ParentImage
falsepositives:
    - Unknown
level: high


```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run AND Details.keyword:(C\\:\\\\Windows\\\\Temp\\\\* C\\:\\\\ProgramData\\\\* *\\\\AppData\\\\* C\\:\\\\$Recycle.bin\\\\* C\\:\\\\Temp\\\\* C\\:\\\\Users\\\\Public\\\\* C\\:\\\\Users\\\\Default\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Registry-Persistence-via-Explorer-Run-Key <<EOF\n{\n  "metadata": {\n    "title": "Registry Persistence via Explorer Run Key",\n    "description": "Detects a possible persistence mechanism using RUN key for Windows Explorer and poiting to a suspicious folder",\n    "tags": [\n      "attack.persistence",\n      "attack.t1060",\n      "capec.270"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Policies\\\\\\\\Explorer\\\\\\\\Run AND Details.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\ProgramData\\\\\\\\* *\\\\\\\\AppData\\\\\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Policies\\\\\\\\Explorer\\\\\\\\Run AND Details.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\ProgramData\\\\\\\\* *\\\\\\\\AppData\\\\\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Registry Persistence via Explorer Run Key\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      Image = {{_source.Image}}\\nParentImage = {{_source.ParentImage}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run" AND Details:("C\\:\\\\Windows\\\\Temp\\\\*" "C\\:\\\\ProgramData\\\\*" "*\\\\AppData\\\\*" "C\\:\\\\$Recycle.bin\\\\*" "C\\:\\\\Temp\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*"))
```


### splunk
    
```
(EventID="13" TargetObject="*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run" (Details="C:\\\\Windows\\\\Temp\\\\*" OR Details="C:\\\\ProgramData\\\\*" OR Details="*\\\\AppData\\\\*" OR Details="C:\\\\$Recycle.bin\\\\*" OR Details="C:\\\\Temp\\\\*" OR Details="C:\\\\Users\\\\Public\\\\*" OR Details="C:\\\\Users\\\\Default\\\\*")) | table Image,ParentImage
```


### logpoint
    
```
(EventID="13" TargetObject="*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run" Details IN ["C:\\\\Windows\\\\Temp\\\\*", "C:\\\\ProgramData\\\\*", "*\\\\AppData\\\\*", "C:\\\\$Recycle.bin\\\\*", "C:\\\\Temp\\\\*", "C:\\\\Users\\\\Public\\\\*", "C:\\\\Users\\\\Default\\\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run)(?=.*(?:.*C:\\Windows\\Temp\\\\.*|.*C:\\ProgramData\\\\.*|.*.*\\AppData\\\\.*|.*C:\\\\$Recycle\\.bin\\\\.*|.*C:\\Temp\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*)))'
```



