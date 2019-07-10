| Title                | NTLM Logon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects logons using NTLM, which could be caused by a legacy source or attackers                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0082_8002_ntlm_server_blocked_audit](../Data_Needed/DN_0082_8002_ntlm_server_blocked_audit.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legacy hosts</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/JohnLaTwC/status/1004895028995477505](https://twitter.com/JohnLaTwC/status/1004895028995477505)</li><li>[https://goo.gl/PsqrhT](https://goo.gl/PsqrhT)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: NTLM Logon
status: experimental
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth
date: 2018/06/08
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: ntlm
    definition: Reqiures events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        CallingProcessName: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```





### es-qs
    
```
(EventID:"8002" AND CallingProcessName.keyword:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/NTLM-Logon <<EOF\n{\n  "metadata": {\n    "title": "NTLM Logon",\n    "description": "Detects logons using NTLM, which could be caused by a legacy source or attackers",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1075"\n    ],\n    "query": "(EventID:\\"8002\\" AND CallingProcessName.keyword:*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"8002\\" AND CallingProcessName.keyword:*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'NTLM Logon\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"8002" AND CallingProcessName:"*")
```


### splunk
    
```
(EventID="8002" CallingProcessName="*")
```


### logpoint
    
```
(EventID="8002" CallingProcessName="*")
```


### grep
    
```
grep -P '^(?:.*(?=.*8002)(?=.*.*))'
```



