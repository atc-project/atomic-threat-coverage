| Title                | Access to ADMIN$ Share                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects access to $ADMIN share                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0033_5140_network_share_object_was_accessed](../Data_Needed/DN_0033_5140_network_share_object_was_accessed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Access to ADMIN$ Share
description: Detects access to $ADMIN share
tags:
    - attack.lateral_movement
    - attack.t1077
status: experimental
author: Florian Roth
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5140
        ShareName: Admin$
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
falsepositives: 
    - Legitimate administrative activity
level: low

```





### es-qs
    
```
((EventID:"5140" AND ShareName:"Admin$") AND (NOT (SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Access-to-ADMIN$-Share <<EOF\n{\n  "metadata": {\n    "title": "Access to ADMIN$ Share",\n    "description": "Detects access to $ADMIN share",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1077"\n    ],\n    "query": "((EventID:\\"5140\\" AND ShareName:\\"Admin$\\") AND (NOT (SubjectUserName.keyword:*$)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"5140\\" AND ShareName:\\"Admin$\\") AND (NOT (SubjectUserName.keyword:*$)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Access to ADMIN$ Share\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"5140" AND ShareName:"Admin$") AND NOT (SubjectUserName:"*$"))
```


### splunk
    
```
((EventID="5140" ShareName="Admin$") NOT (SubjectUserName="*$"))
```


### logpoint
    
```
((EventID="5140" ShareName="Admin$")  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5140)(?=.*Admin\\$)))(?=.*(?!.*(?:.*(?=.*.*\\$)))))'
```



