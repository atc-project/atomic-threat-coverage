| Title                | Suspicious Program Location with Network Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs with network connections running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location with Network Connections
status: experimental
description: Detects programs with network connections running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
author: Florian Roth
date: 2017/03/19
logsource:
    product: windows
    service: sysmon
    definition: 'Use the following config to generate the necessary Event ID 3 Network Connection events'
detection:
    selection:
        EventID: 3
        Image: 
            # - '*\ProgramData\\*'  # too many false positives, e.g. with Webex for Windows
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - '*\Users\Contacts\\*'
            - '*\Users\Searches\\*' 
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"3" AND Image.keyword:(*\\\\$Recycle.bin *\\\\Users\\\\All\\ Users\\\\* *\\\\Users\\\\Default\\\\* *\\\\Users\\\\Public\\\\* *\\\\Users\\\\Contacts\\\\* *\\\\Users\\\\Searches\\\\* C\\:\\\\Perflogs\\\\* *\\\\config\\\\systemprofile\\\\* *\\\\Windows\\\\Fonts\\\\* *\\\\Windows\\\\IME\\\\* *\\\\Windows\\\\addins\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Program-Location-with-Network-Connections <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Program Location with Network Connections",\n    "description": "Detects programs with network connections running in suspicious files system locations",\n    "tags": "",\n    "query": "(EventID:\\"3\\" AND Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\All\\\\ Users\\\\\\\\* *\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* *\\\\\\\\Users\\\\\\\\Contacts\\\\\\\\* *\\\\\\\\Users\\\\\\\\Searches\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"3\\" AND Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\All\\\\ Users\\\\\\\\* *\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* *\\\\\\\\Users\\\\\\\\Contacts\\\\\\\\* *\\\\\\\\Users\\\\\\\\Searches\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\config\\\\\\\\systemprofile\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Program Location with Network Connections\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"3" AND Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\All Users\\\\*" "*\\\\Users\\\\Default\\\\*" "*\\\\Users\\\\Public\\\\*" "*\\\\Users\\\\Contacts\\\\*" "*\\\\Users\\\\Searches\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\config\\\\systemprofile\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*"))
```


### splunk
    
```
(EventID="3" (Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\All Users\\\\*" OR Image="*\\\\Users\\\\Default\\\\*" OR Image="*\\\\Users\\\\Public\\\\*" OR Image="*\\\\Users\\\\Contacts\\\\*" OR Image="*\\\\Users\\\\Searches\\\\*" OR Image="C:\\\\Perflogs\\\\*" OR Image="*\\\\config\\\\systemprofile\\\\*" OR Image="*\\\\Windows\\\\Fonts\\\\*" OR Image="*\\\\Windows\\\\IME\\\\*" OR Image="*\\\\Windows\\\\addins\\\\*"))
```


### logpoint
    
```
(EventID="3" Image IN ["*\\\\$Recycle.bin", "*\\\\Users\\\\All Users\\\\*", "*\\\\Users\\\\Default\\\\*", "*\\\\Users\\\\Public\\\\*", "*\\\\Users\\\\Contacts\\\\*", "*\\\\Users\\\\Searches\\\\*", "C:\\\\Perflogs\\\\*", "*\\\\config\\\\systemprofile\\\\*", "*\\\\Windows\\\\Fonts\\\\*", "*\\\\Windows\\\\IME\\\\*", "*\\\\Windows\\\\addins\\\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\\\$Recycle\\.bin|.*.*\\Users\\All Users\\\\.*|.*.*\\Users\\Default\\\\.*|.*.*\\Users\\Public\\\\.*|.*.*\\Users\\Contacts\\\\.*|.*.*\\Users\\Searches\\\\.*|.*C:\\Perflogs\\\\.*|.*.*\\config\\systemprofile\\\\.*|.*.*\\Windows\\Fonts\\\\.*|.*.*\\Windows\\IME\\\\.*|.*.*\\Windows\\addins\\\\.*)))'
```



