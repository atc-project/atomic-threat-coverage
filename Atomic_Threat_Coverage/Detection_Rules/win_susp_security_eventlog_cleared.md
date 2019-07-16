| Title                | Security Eventlog Cleared                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| Data Needed          | <ul><li>[DN_0050_1102_audit_log_was_cleared](../Data_Needed/DN_0050_1102_audit_log_was_cleared.md)</li><li>[DN_0038_1102_the_audit_log_was_cleared](../Data_Needed/DN_0038_1102_the_audit_log_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)</li><li>System provisioning (system reset before the golden image creation)</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2016-04-002</li><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Security Eventlog Cleared
description: Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities
tags:
    - attack.defense_evasion
    - attack.t1070
    - car.2016-04-002
author: Florian Roth
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 517
            - 1102
    condition: selection
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high

```





### es-qs
    
```
EventID:("517" "1102")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Security-Eventlog-Cleared <<EOF\n{\n  "metadata": {\n    "title": "Security Eventlog Cleared",\n    "description": "Some threat groups tend to delete the local \'Security\' Eventlog using certain utitlities",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070",\n      "car.2016-04-002"\n    ],\n    "query": "EventID:(\\"517\\" \\"1102\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:(\\"517\\" \\"1102\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Security Eventlog Cleared\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("517" "1102")
```


### splunk
    
```
(EventID="517" OR EventID="1102")
```


### logpoint
    
```
EventID IN ["517", "1102"]
```


### grep
    
```
grep -P '^(?:.*517|.*1102)'
```



