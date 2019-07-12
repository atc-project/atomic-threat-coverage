| Title                | Suspicious Driver Load from Temp                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a driver load from a temporary directory                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| Data Needed          | <ul><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>there is a relevant set of false positives depending on applications in the environment</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Driver Load from Temp
description: Detects a driver load from a temporary directory
author: Florian Roth
tags: 
  - attack.persistence
  - attack.t1050
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
        ImageLoaded: '*\Temp\\*'
    condition: selection
falsepositives:
    - there is a relevant set of false positives depending on applications in the environment 
level: medium

```





### es-qs
    
```
(EventID:"6" AND ImageLoaded.keyword:*\\\\Temp\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Driver-Load-from-Temp <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Driver Load from Temp",\n    "description": "Detects a driver load from a temporary directory",\n    "tags": [\n      "attack.persistence",\n      "attack.t1050"\n    ],\n    "query": "(EventID:\\"6\\" AND ImageLoaded.keyword:*\\\\\\\\Temp\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"6\\" AND ImageLoaded.keyword:*\\\\\\\\Temp\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Driver Load from Temp\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"6" AND ImageLoaded:"*\\\\Temp\\\\*")
```


### splunk
    
```
(EventID="6" ImageLoaded="*\\\\Temp\\\\*")
```


### logpoint
    
```
(EventID="6" ImageLoaded="*\\\\Temp\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*6)(?=.*.*\\Temp\\\\.*))'
```



