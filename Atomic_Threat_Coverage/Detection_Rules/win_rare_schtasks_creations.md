| Title                | Rare Schtasks Creations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| Data Needed          | <ul><li>[DN_0064_4698_scheduled_task_was_created](../Data_Needed/DN_0064_4698_scheduled_task_was_created.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Software installation</li><li>Software updates</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Schtasks Creations
description: Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code
status: experimental
author: Florian Roth
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1053
    - car.2013-08-001
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection (not in the baseline recommendations by Microsoft). We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection:
        EventID: 4698
    timeframe: 7d
    condition: selection | count() by TaskName < 5 
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
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Rare-Schtasks-Creations <<EOF\n{\n  "metadata": {\n    "title": "Rare Schtasks Creations",\n    "description": "Detects rare scheduled tasks creations that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious code",\n    "tags": [\n      "attack.execution",\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.t1053",\n      "car.2013-08-001"\n    ],\n    "query": "EventID:\\"4698\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "7d"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"4698\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          },\n          "aggs": {\n            "by": {\n              "terms": {\n                "field": "TaskName.keyword",\n                "size": 10,\n                "order": {\n                  "_count": "asc"\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.aggregations.by.buckets.0.doc_count": {\n        "lt": 5\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Rare Schtasks Creations\'",\n        "body": "Hits:\\n{{#aggregations.by.buckets}}\\n {{key}} {{doc_count}}\\n{{/aggregations.by.buckets}}\\n",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```

```


### splunk
    
```
EventID="4698" | eventstats count as val by TaskName| search val < 5
```


### logpoint
    
```
EventID="4698" | chart count() as val by TaskName | search val < 5
```


### grep
    
```
grep -P '^4698'
```



