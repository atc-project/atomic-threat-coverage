| Title                    | Registy Entries For Azorult Malware       |
|:-------------------------|:------------------|
| **Description**          | Detects the presence of a registry key created during Azorult execution |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a)</li></ul>  |
| **Author**               | Trent Liffick |


## Detection Rules

### Sigma rule

```
title: Registy Entries For Azorult Malware
id: f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7
description: Detects the presence of a registry key created during Azorult execution
status: experimental
references:
  - https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a
author: Trent Liffick
date: 2020/05/08
tags:
  - attack.execution
  - attack.t1112
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 12
      - 13
    TargetObject:
      - '*SYSTEM\\*\services\localNETService'
  condition: selection
fields:
  - Image
  - TargetObject
  - TargetDetails
falsepositives:
  - unknown
level: critical

```





### es-qs
    
```
(EventID:("12" OR "13") AND TargetObject.keyword:(*SYSTEM\\\\*\\\\services\\\\localNETService))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7 <<EOF\n{\n  "metadata": {\n    "title": "Registy Entries For Azorult Malware",\n    "description": "Detects the presence of a registry key created during Azorult execution",\n    "tags": [\n      "attack.execution",\n      "attack.t1112"\n    ],\n    "query": "(EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*SYSTEM\\\\\\\\*\\\\\\\\services\\\\\\\\localNETService))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*SYSTEM\\\\\\\\*\\\\\\\\services\\\\\\\\localNETService))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Registy Entries For Azorult Malware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n        Image = {{_source.Image}}\\n TargetObject = {{_source.TargetObject}}\\nTargetDetails = {{_source.TargetDetails}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("12" "13") AND TargetObject.keyword:(*SYSTEM\\\\*\\\\services\\\\localNETService))
```


### splunk
    
```
((EventID="12" OR EventID="13") (TargetObject="*SYSTEM\\\\*\\\\services\\\\localNETService")) | table Image,TargetObject,TargetDetails
```


### logpoint
    
```
(event_id IN ["12", "13"] TargetObject IN ["*SYSTEM\\\\*\\\\services\\\\localNETService"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*.*SYSTEM\\\\.*\\services\\localNETService)))'
```



