| Title                | Rare Service Installs                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-09-005</li><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Service Installs
description: Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services 
status: experimental
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
    - car.2013-09-005
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    timeframe: 7d
    condition: selection | count() by ServiceFileName < 5 
falsepositives: 
    - Software installation
    - Software updates
level: low
```





### es-qs
    
```

```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Rare-Service-Installs <<EOF\n{\n  "metadata": {\n    "title": "Rare Service Installs",\n    "description": "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1050",\n      "car.2013-09-005"\n    ],\n    "query": "EventID:\\"7045\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "7d"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"7045\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "ServiceFileName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "asc"\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "lt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rare Service Installs\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
EventID="7045" | eventstats count as val by ServiceFileName| search val < 5
```


### logpoint
    
```
EventID="7045" | chart count() as val by ServiceFileName | search val < 5
```


### grep
    
```
grep -P '^7045'
```



