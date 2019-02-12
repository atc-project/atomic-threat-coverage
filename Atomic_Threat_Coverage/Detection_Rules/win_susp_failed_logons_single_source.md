| Title                | Multiple Failed Logins with Different Accounts from Single Source System                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious failed logins with different user accounts from a single source system                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/tactics/T1078)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[('Valid Accounts', 'T1078')](../Triggers/('Valid Accounts', 'T1078').md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Terminal servers</li><li>Jump servers</li><li>Other multiuser systems like Citrix server farms</li><li>Workstations with frequently changing users</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.privilege_escalation</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Multiple Failed Logins with Different Accounts from Single Source System
description: Detects suspicious failed logins with different user accounts from a single source system 
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 529
            - 4625
        UserName: '*'
        WorkstationName: '*'
    selection2:
        EventID: 4776
        UserName: '*'
        Workstation: '*'
    timeframe: 24h 
    condition:
        - selection1 | count(UserName) by WorkstationName > 3
        - selection2 | count(UserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users 
level: medium



```








### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Multiple-Failed-Logins-with-Different-Accounts-from-Single-Source-System <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "24h"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4776\\" AND UserName.keyword:* AND Workstation.keyword:*)",\n              "analyze_wildcard": true\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "Workstation.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 4\n              },\n              "aggs": {\n                "agg": {\n                  "terms": {\n                    "field": "UserName.keyword",\n                    "size": 10,\n                    "order": {\n                      "_count": "desc"\n                    },\n                    "min_doc_count": 4\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.agg.buckets.0.doc_count": {\n        "gt": 3\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Multiple Failed Logins with Different Accounts from Single Source System\'",\n        "body": "Hits:\\n{{#aggregations.agg.buckets}}\\n {{key}} {{doc_count}}\\n\\n{{#by.buckets}}\\n-- {{key}} {{doc_count}}\\n{{/by.buckets}}\\n\\n{{/aggregations.agg.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```




