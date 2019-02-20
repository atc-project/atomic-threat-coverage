| Title                | Suspicious Program Location Process Starts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects programs running in suspicious files system locations                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Program Location Process Starts
status: experimental
description: Detects programs running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
author: Florian Roth
date: 2019/01/15
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: 
            # - '*\ProgramData\\*'  # too many false positives, e.g. with Webex for Windows
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





### Kibana query

```
(EventID:"1" AND Image.keyword:(*\\\\$Recycle.bin *\\\\Users\\\\Public\\\\* C\\:\\\\Perflogs\\\\* *\\\\Windows\\\\Fonts\\\\* *\\\\Windows\\\\IME\\\\* *\\\\Windows\\\\addins\\\\* *\\\\Windows\\\\debug\\\\*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Program-Location-Process-Starts <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:(*\\\\\\\\$Recycle.bin *\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Perflogs\\\\\\\\* *\\\\\\\\Windows\\\\\\\\Fonts\\\\\\\\* *\\\\\\\\Windows\\\\\\\\IME\\\\\\\\* *\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* *\\\\\\\\Windows\\\\\\\\debug\\\\\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Program Location Process Starts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND Image:("*\\\\$Recycle.bin" "*\\\\Users\\\\Public\\\\*" "C\\:\\\\Perflogs\\\\*" "*\\\\Windows\\\\Fonts\\\\*" "*\\\\Windows\\\\IME\\\\*" "*\\\\Windows\\\\addins\\\\*" "*\\\\Windows\\\\debug\\\\*"))
```

