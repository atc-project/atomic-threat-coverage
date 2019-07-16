| Title                | Detects local user creation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Domain Controller Logs</li><li>Local accounts managed by privileged account management tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/](https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/)</li></ul>  |
| Author               | Patrick Bareiss |


## Detection Rules

### Sigma rule

```
title: Detects local user creation
description: Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs. 
status: experimental
tags:
    - attack.persistence
    - attack.t1136
references:
    - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/ 
author: Patrick Bareiss
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
fields:
    - EventCode
    - AccountName
    - AccountDomain
falsepositives: 
    - Domain Controller Logs
    - Local accounts managed by privileged account management tools
level: low



```





### es-qs
    
```
EventID:"4720"
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Detects-local-user-creation <<EOF\n{\n  "metadata": {\n    "title": "Detects local user creation",\n    "description": "Detects local user creation on windows servers, which shouldn\'t happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1136"\n    ],\n    "query": "EventID:\\"4720\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"4720\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Detects local user creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n    EventCode = {{_source.EventCode}}\\n  AccountName = {{_source.AccountName}}\\nAccountDomain = {{_source.AccountDomain}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:"4720"
```


### splunk
    
```
EventID="4720" | table EventCode,AccountName,AccountDomain
```


### logpoint
    
```
EventID="4720"
```


### grep
    
```
grep -P '^4720'
```



