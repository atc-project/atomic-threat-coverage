| Title                | WMI Event Subscription                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects creation of WMI event subscription persistence method                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| Data Needed          | <ul><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li><li>[DN_0024_21_windows_sysmon_WmiEvent](../Data_Needed/DN_0024_21_windows_sysmon_WmiEvent.md)</li><li>[DN_0022_19_windows_sysmon_WmiEvent](../Data_Needed/DN_0022_19_windows_sysmon_WmiEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>exclude legitimate (vetted) use of WMI event subscription in your network</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1084/](https://attack.mitre.org/techniques/T1084/)</li></ul>  |
| Author               | Tom Ueltschi (@c_APT_ure) |


## Detection Rules

### Sigma rule

```
title: WMI Event Subscription
status: experimental
description: Detects creation of WMI event subscription persistence method
references:
    - https://attack.mitre.org/techniques/T1084/
tags:
    - attack.t1084
    - attack.persistence
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID:
            - 19
            - 20
            - 21
    condition: selector
falsepositives:
    - exclude legitimate (vetted) use of WMI event subscription in your network
level: high

```





### es-qs
    
```
EventID:("19" "20" "21")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/WMI-Event-Subscription <<EOF\n{\n  "metadata": {\n    "title": "WMI Event Subscription",\n    "description": "Detects creation of WMI event subscription persistence method",\n    "tags": [\n      "attack.t1084",\n      "attack.persistence"\n    ],\n    "query": "EventID:(\\"19\\" \\"20\\" \\"21\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:(\\"19\\" \\"20\\" \\"21\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'WMI Event Subscription\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("19" "20" "21")
```


### splunk
    
```
(EventID="19" OR EventID="20" OR EventID="21")
```


### logpoint
    
```
EventID IN ["19", "20", "21"]
```


### grep
    
```
grep -P '^(?:.*19|.*20|.*21)'
```



