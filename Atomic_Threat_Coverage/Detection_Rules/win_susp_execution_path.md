| Title                | Execution in Non-Executable Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious exection from an uncommon folder                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Execution in Non-Executable Folder
status: experimental
description: Detects a suspicious exection from an uncommon folder
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
Image.keyword:(*\\\\$Recycle.bin *\\\\Users\\\\All\\ Users\\\\* *\\\\Users\\\\Default\\\\* *\\\\Users\\\\Public\\\\* C\\:\\\\Perflogs\\\\* *\\\\config\\\\systemprofile\\\\* *\\\\Windows\\\\Fonts\\\\* *\\\\Windows\\\\IME\\\\* *\\\\Windows\\\\addins\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Execution-in-Non-Executable-Folder <<EOF\n{\n  "metadata": {\n    "title": "Execution in Non-Executable Folder",\n    "description": "Detects a suspicious exection from an uncommon folder",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\All\\\\ Users\\\\\\\\* *\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\All\\\\ Users\\\\\\\\* *\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Execution in Non-Executable Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\All Users\\\\*" "*\\\\Users\\\\Default\\\\*" "*\\\\Users\\\\Public\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\config\\\\systemprofile\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*")
```


### splunk
    
```
(Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\All Users\\\\*" OR Image="*\\\\Users\\\\Default\\\\*" OR Image="*\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Perflogs\\\\*" OR Image="*\\\\config\\\\systemprofile\\\\*" OR Image="*\\\\Windows\\\\Fonts\\\\*" OR Image="*\\\\Windows\\\\IME\\\\*" OR Image="*\\\\Windows\\\\addins\\\\*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
Image IN ["*\\\\$Recycle.bin", "*\\\\Users\\\\All Users\\\\*", "*\\\\Users\\\\Default\\\\*", "*\\\\Users\\\\Public\\\\*", "C:\\\\Perflogs\\\\*", "*\\\\config\\\\systemprofile\\\\*", "*\\\\Windows\\\\Fonts\\\\*", "*\\\\Windows\\\\IME\\\\*", "*\\\\Windows\\\\addins\\\\*"]
```


### grep
    
```
grep -P '^(?:.*.*\\\\$Recycle\\.bin|.*.*\\Users\\All Users\\\\.*|.*.*\\Users\\Default\\\\.*|.*.*\\Users\\Public\\\\.*|.*C:\\Perflogs\\\\.*|.*.*\\config\\systemprofile\\\\.*|.*.*\\Windows\\Fonts\\\\.*|.*.*\\Windows\\IME\\\\.*|.*.*\\Windows\\addins\\\\.*)'
```



