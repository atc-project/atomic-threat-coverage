| Title                | Rare Scheduled Task Creations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0035_106_task_scheduler_task_registered](../Data_Needed/DN_0035_106_task_scheduler_task_registered.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Scheduled Task Creations
status: experimental
description: This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names. 
tags:
    - attack.persistence
    - attack.t1053
    - attack.s0111
author: Florian Roth
logsource:
    product: windows
    service: taskscheduler
detection:
    selection:
        EventID: 106
    timeframe: 7d
    condition: selection | count() by TaskName < 5 
falsepositives:
    - Software installation
level: low

```





### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Rare-Scheduled-Task-Creations <<EOF\n{\n  "metadata": {\n    "title": "Rare Scheduled Task Creations",\n    "description": "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1053",\n      "attack.s0111"\n    ],\n    "query": "EventID:\\"106\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "7d"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"106\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "TaskName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "asc"\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "lt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rare Scheduled Task Creations\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
EventID="106" | eventstats count as val by TaskName| search val < 5
```


### logpoint
    
```
EventID="106" | chart count() as val by TaskName | search val < 5
```


### grep
    
```
grep -P '^106'
```



