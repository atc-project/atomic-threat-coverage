| Title                | Suspicious Program Location Process Starts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location Process Starts
status: experimental
description: Detects programs running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2019/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
            - '*\Windows\debug\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
Image.keyword:(*\\\\$Recycle.bin *\\\\Users\\\\Public\\\\* C\\:\\\\Perflogs\\\\* *\\\\Windows\\\\Fonts\\\\* *\\\\Windows\\\\IME\\\\* *\\\\Windows\\\\addins\\\\* *\\\\Windows\\\\debug\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Program-Location-Process-Starts <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Program Location Process Starts",\n    "description": "Detects programs running in suspicious files system locations",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* *\\\\\\\\Windows\\\\\\\\debug\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* *\\\\\\\\Windows\\\\\\\\debug\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Program Location Process Starts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\Public\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*" "*\\\\Windows\\\\debug\\\\*")
```


### splunk
    
```
(Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\Public\\\\*" OR Image="C:\\\\Perflogs\\\\*" OR Image="*\\\\Windows\\\\Fonts\\\\*" OR Image="*\\\\Windows\\\\IME\\\\*" OR Image="*\\\\Windows\\\\addins\\\\*" OR Image="*\\\\Windows\\\\debug\\\\*")
```


### logpoint
    
```
Image IN ["*\\\\$Recycle.bin", "*\\\\Users\\\\Public\\\\*", "C:\\\\Perflogs\\\\*", "*\\\\Windows\\\\Fonts\\\\*", "*\\\\Windows\\\\IME\\\\*", "*\\\\Windows\\\\addins\\\\*", "*\\\\Windows\\\\debug\\\\*"]
```


### grep
    
```
grep -P '^(?:.*.*\\\\$Recycle\\.bin|.*.*\\Users\\Public\\\\.*|.*C:\\Perflogs\\\\.*|.*.*\\Windows\\Fonts\\\\.*|.*.*\\Windows\\IME\\\\.*|.*.*\\Windows\\addins\\\\.*|.*.*\\Windows\\debug\\\\.*)'
```



