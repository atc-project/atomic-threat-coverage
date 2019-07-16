| Title                | Multiple Failed Logins with Different Accounts from Single Source System                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious failed logins with different user accounts from a single source system                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Terminal servers</li><li>Jump servers</li><li>Other multiuser systems like Citrix server farms</li><li>Workstations with frequently changing users</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


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





### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Multiple-Failed-Logins-with-Different-Accounts-from-Single-Source-System <<EOF\n{\n  "metadata": {\n    "title": "Multiple Failed Logins with Different Accounts from Single Source System",\n    "description": "Detects suspicious failed logins with different user accounts from a single source system",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1078"\n    ],\n    "query": "(EventID:(\\"529\\" \\"4625\\") AND UserName.keyword:* AND WorkstationName.keyword:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "24h"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"529\\" \\"4625\\") AND UserName.keyword:* AND WorkstationName.keyword:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "WorkstationName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 4\n              },\n              "aggs": {\n                "agg": {\n                  "terms": {\n                    "field": "UserName.keyword",\n                    "size": 10,\n                    "order": {\n                      "_count": "desc"\n                    },\n                    "min_doc_count": 4\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.agg.buckets.0.doc_count": {\n        "gt": 3\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Multiple Failed Logins with Different Accounts from Single Source System\'",\n        "body": "Hits:\\n{{#aggregations.agg.buckets}}\\n {{key}} {{doc_count}}\\n\\n{{#by.buckets}}\\n-- {{key}} {{doc_count}}\\n{{/by.buckets}}\\n\\n{{/aggregations.agg.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Multiple-Failed-Logins-with-Different-Accounts-from-Single-Source-System-2 <<EOF\n{\n  "metadata": {\n    "title": "Multiple Failed Logins with Different Accounts from Single Source System",\n    "description": "Detects suspicious failed logins with different user accounts from a single source system",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1078"\n    ],\n    "query": "(EventID:\\"4776\\" AND UserName.keyword:* AND Workstation.keyword:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "24h"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4776\\" AND UserName.keyword:* AND Workstation.keyword:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "Workstation.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "desc"\n                },\n                "min_doc_count": 4\n              },\n              "aggs": {\n                "agg": {\n                  "terms": {\n                    "field": "UserName.keyword",\n                    "size": 10,\n                    "order": {\n                      "_count": "desc"\n                    },\n                    "min_doc_count": 4\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.agg.buckets.0.doc_count": {\n        "gt": 3\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Multiple Failed Logins with Different Accounts from Single Source System\'",\n        "body": "Hits:\\n{{#aggregations.agg.buckets}}\\n {{key}} {{doc_count}}\\n\\n{{#by.buckets}}\\n-- {{key}} {{doc_count}}\\n{{/by.buckets}}\\n\\n{{/aggregations.agg.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
((EventID="529" OR EventID="4625") UserName="*" WorkstationName="*") | eventstats dc(UserName) as val by WorkstationName | search val > 3
```


### logpoint
    
```
(EventID IN ["529", "4625"] UserName="*" WorkstationName="*") | chart count(UserName) as val by WorkstationName | search val > 3
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*529|.*4625))(?=.*.*)(?=.*.*))'
```



