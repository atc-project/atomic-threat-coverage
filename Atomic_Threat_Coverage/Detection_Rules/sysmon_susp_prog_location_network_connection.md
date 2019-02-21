| Title                | Suspicious Program Location with Network Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs with network connections running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


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
            - '*\ProgramData\*'
            - '*\$Recycle.bin'
            - '*\Users\All Users\*'
            - '*\Users\Default\*'
            - '*\Users\Public\*'
            - 'C:\Perflogs\*'
            - '*\config\systemprofile\*'
            - '*\Windows\Fonts\*'
            - '*\Windows\IME\*'
            - '*\Windows\addins\*'
    condition: selection
falsepositives:
    - unknown
level: high
```





### Kibana query

```
(EventID:"3" AND Image.keyword:(*\\\\ProgramData\\* *\\\\$Recycle.bin *\\\\Users\\\\All\\ Users\\* *\\\\Users\\\\Default\\* *\\\\Users\\\\Public\\* C\\:\\\\Perflogs\\* *\\\\config\\\\systemprofile\\* *\\\\Windows\\\\Fonts\\* *\\\\Windows\\\\IME\\* *\\\\Windows\\\\addins\\*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Program-Location-with-Network-Connections <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"3\\" AND Image.keyword:(*\\\\\\\\ProgramData\\\\* *\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\All\\\\ Users\\\\* *\\\\\\\\Users\\\\\\\\Default\\\\* *\\\\\\\\Users\\\\\\\\Public\\\\* C\\\\:\\\\\\\\Perflogs\\\\* *\\\\\\\\config\\\\\\\\systemprofile\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Program Location with Network Connections\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"3" AND Image:("*\\\\ProgramData\\*" "*\\\\$Recycle.bin" "*\\\\Users\\\\All Users\\*" "*\\\\Users\\\\Default\\*" "*\\\\Users\\\\Public\\*" "C\\:\\\\Perflogs\\*" "*\\\\config\\\\systemprofile\\*" "*\\\\Windows\\\\Fonts\\*" "*\\\\Windows\\\\IME\\*" "*\\\\Windows\\\\addins\\*"))
```





### Splunk

```
(EventID="3" (Image="*\\\\ProgramData\\*" OR Image="*\\\\$Recycle.bin" OR Image="*\\\\Users\\\\All Users\\*" OR Image="*\\\\Users\\\\Default\\*" OR Image="*\\\\Users\\\\Public\\*" OR Image="C:\\\\Perflogs\\*" OR Image="*\\\\config\\\\systemprofile\\*" OR Image="*\\\\Windows\\\\Fonts\\*" OR Image="*\\\\Windows\\\\IME\\*" OR Image="*\\\\Windows\\\\addins\\*"))
```





### Logpoint

```
(EventID="3" Image IN ["*\\\\ProgramData\\*", "*\\\\$Recycle.bin", "*\\\\Users\\\\All Users\\*", "*\\\\Users\\\\Default\\*", "*\\\\Users\\\\Public\\*", "C:\\\\Perflogs\\*", "*\\\\config\\\\systemprofile\\*", "*\\\\Windows\\\\Fonts\\*", "*\\\\Windows\\\\IME\\*", "*\\\\Windows\\\\addins\\*"])
```





### Grep

```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\ProgramData\\.*|.*.*\\\\$Recycle\\.bin|.*.*\\Users\\All Users\\.*|.*.*\\Users\\Default\\.*|.*.*\\Users\\Public\\.*|.*C:\\Perflogs\\.*|.*.*\\config\\systemprofile\\.*|.*.*\\Windows\\Fonts\\.*|.*.*\\Windows\\IME\\.*|.*.*\\Windows\\addins\\.*)))'
```





### Fieldlist

```
EventID\nImage
```

