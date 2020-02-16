| Title                | Cred dump-tools named pipes                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects well-known credential dumping tools execution via specific named pipes                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate Administrator using tool for password recovery</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| Author               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Cred dump-tools named pipes
id: 961d0ba2-3eea-4303-a930-2cf78bbfcc5e
description: Detects well-known credential dumping tools execution via specific named pipes
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 17
        PipeName|contains:
            - '\lsadump'
            - '\cachedump'
            - '\wceservicepipe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: medium
status: experimental

```





### es-qs
    
```
(EventID:"17" AND PipeName.keyword:(*\\\\lsadump* OR *\\\\cachedump* OR *\\\\wceservicepipe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Cred-dump-tools-named-pipes <<EOF\n{\n  "metadata": {\n    "title": "Cred dump-tools named pipes",\n    "description": "Detects well-known credential dumping tools execution via specific named pipes",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"17\\" AND PipeName.keyword:(*\\\\\\\\lsadump* OR *\\\\\\\\cachedump* OR *\\\\\\\\wceservicepipe*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"17\\" AND PipeName.keyword:(*\\\\\\\\lsadump* OR *\\\\\\\\cachedump* OR *\\\\\\\\wceservicepipe*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Cred dump-tools named pipes\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"17" AND PipeName.keyword:(*\\\\lsadump* *\\\\cachedump* *\\\\wceservicepipe*))
```


### splunk
    
```
(EventID="17" (PipeName="*\\\\lsadump*" OR PipeName="*\\\\cachedump*" OR PipeName="*\\\\wceservicepipe*"))
```


### logpoint
    
```
(event_id="17" PipeName IN ["*\\\\lsadump*", "*\\\\cachedump*", "*\\\\wceservicepipe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*17)(?=.*(?:.*.*\\lsadump.*|.*.*\\cachedump.*|.*.*\\wceservicepipe.*)))'
```



