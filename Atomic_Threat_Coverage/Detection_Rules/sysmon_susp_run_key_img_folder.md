| Title                | New RUN Key Pointing to Suspicious Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious new RUN key element pointing to an executable in a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Software with rare behaviour</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)</li></ul>  |
| Author               | Florian Roth, Markus Neis |


## Detection Rules

### Sigma rule

```
title: New RUN Key Pointing to Suspicious Folder
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth, Markus Neis
tags:
    - attack.persistence
    - attack.t1060
date: 2018/25/08
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
          - '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\\*'
        Details:
          - 'C:\Windows\Temp\\*'
          - '*\AppData\\*'
          - 'C:\$Recycle.bin\\*'
          - 'C:\Temp\\*'
          - 'C:\Users\Public\\*'
          - 'C:\Users\Default\\*'
          - 'C:\Users\Desktop\\*'
    condition: selection
fields:
    - Image
falsepositives:
    - Software with rare behaviour
level: high

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\* *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*) AND Details.keyword:(C\\:\\\\Windows\\\\Temp\\\\* *\\\\AppData\\\\* C\\:\\\\$Recycle.bin\\\\* C\\:\\\\Temp\\\\* C\\:\\\\Users\\\\Public\\\\* C\\:\\\\Users\\\\Default\\\\* C\\:\\\\Users\\\\Desktop\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/New-RUN-Key-Pointing-to-Suspicious-Folder <<EOF\n{\n  "metadata": {\n    "title": "New RUN Key Pointing to Suspicious Folder",\n    "description": "Detects suspicious new RUN key element pointing to an executable in a suspicious folder",\n    "tags": [\n      "attack.persistence",\n      "attack.t1060"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\\\\\\\\* *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce\\\\\\\\*) AND Details.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* *\\\\\\\\AppData\\\\\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Desktop\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run\\\\\\\\* *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce\\\\\\\\*) AND Details.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* *\\\\\\\\AppData\\\\\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Desktop\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'New RUN Key Pointing to Suspicious Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nImage = {{_source.Image}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*") AND Details:("C\\:\\\\Windows\\\\Temp\\\\*" "*\\\\AppData\\\\*" "C\\:\\\\$Recycle.bin\\\\*" "C\\:\\\\Temp\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*" "C\\:\\\\Users\\\\Desktop\\\\*"))
```


### splunk
    
```
(EventID="13" (TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*") (Details="C:\\\\Windows\\\\Temp\\\\*" OR Details="*\\\\AppData\\\\*" OR Details="C:\\\\$Recycle.bin\\\\*" OR Details="C:\\\\Temp\\\\*" OR Details="C:\\\\Users\\\\Public\\\\*" OR Details="C:\\\\Users\\\\Default\\\\*" OR Details="C:\\\\Users\\\\Desktop\\\\*")) | table Image
```


### logpoint
    
```
(EventID="13" TargetObject IN ["*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*"] Details IN ["C:\\\\Windows\\\\Temp\\\\*", "*\\\\AppData\\\\*", "C:\\\\$Recycle.bin\\\\*", "C:\\\\Temp\\\\*", "C:\\\\Users\\\\Public\\\\*", "C:\\\\Users\\\\Default\\\\*", "C:\\\\Users\\\\Desktop\\\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\\\.*|.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\\\.*))(?=.*(?:.*C:\\Windows\\Temp\\\\.*|.*.*\\AppData\\\\.*|.*C:\\\\$Recycle\\.bin\\\\.*|.*C:\\Temp\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*|.*C:\\Users\\Desktop\\\\.*)))'
```



