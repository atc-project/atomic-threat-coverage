| Title                | T1012 SAM Registry Hive Handle Request                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects handles requested to SAM registry hive                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li></ul>  |
| Data Needed          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| Trigger              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1012 SAM Registry Hive Handle Request
id: f8748f2c-89dc-4d95-afb0-5a2dfdbad332
description: Detects handles requested to SAM registry hive
status: experimental
date: 2019/08/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'Key'
        ObjectName|endswith: '\SAM'
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(EventID:"4656" AND ObjectType:"Key" AND ObjectName.keyword:*\\\\SAM)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1012-SAM-Registry-Hive-Handle-Request <<EOF\n{\n  "metadata": {\n    "title": "T1012 SAM Registry Hive Handle Request",\n    "description": "Detects handles requested to SAM registry hive",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012"\n    ],\n    "query": "(EventID:\\"4656\\" AND ObjectType:\\"Key\\" AND ObjectName.keyword:*\\\\\\\\SAM)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4656\\" AND ObjectType:\\"Key\\" AND ObjectName.keyword:*\\\\\\\\SAM)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1012 SAM Registry Hive Handle Request\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4656" AND ObjectType:"Key" AND ObjectName.keyword:*\\\\SAM)
```


### splunk
    
```
(EventID="4656" ObjectType="Key" ObjectName="*\\\\SAM")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ObjectType="Key" ObjectName="*\\\\SAM")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*Key)(?=.*.*\\SAM))'
```



