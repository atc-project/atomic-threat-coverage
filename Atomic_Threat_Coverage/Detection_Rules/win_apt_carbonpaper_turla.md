| Title                    | Turla Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0010</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Turla Service Install
id: 1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4
description: This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET
references:
    - https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
tags:
    - attack.persistence
    - attack.g0010
    - attack.t1050
date: 2017/03/31
author: Florian Roth
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName:
            - 'srservice'
            - 'ipvpn'
            - 'hkmsvc'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"7045" AND ServiceName:("srservice" OR "ipvpn" OR "hkmsvc"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4 <<EOF\n{\n  "metadata": {\n    "title": "Turla Service Install",\n    "description": "This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET",\n    "tags": [\n      "attack.persistence",\n      "attack.g0010",\n      "attack.t1050"\n    ],\n    "query": "(EventID:\\"7045\\" AND ServiceName:(\\"srservice\\" OR \\"ipvpn\\" OR \\"hkmsvc\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7045\\" AND ServiceName:(\\"srservice\\" OR \\"ipvpn\\" OR \\"hkmsvc\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Turla Service Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND ServiceName:("srservice" "ipvpn" "hkmsvc"))
```


### splunk
    
```
(EventID="7045" (ServiceName="srservice" OR ServiceName="ipvpn" OR ServiceName="hkmsvc"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" service IN ["srservice", "ipvpn", "hkmsvc"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*srservice|.*ipvpn|.*hkmsvc)))'
```



