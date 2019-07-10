| Title                | Ursnif                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects new registry key created by Ursnif malware.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://blog.yoroi.company/research/ursnif-long-live-the-steganography/](https://blog.yoroi.company/research/ursnif-long-live-the-steganography/)</li><li>[https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/](https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/)</li></ul>  |
| Author               | megan201296 |


## Detection Rules

### Sigma rule

```
title: Ursnif
status: experimental
description: Detects new registry key created by Ursnif malware. 
references:
    - https://blog.yoroi.company/research/ursnif-long-live-the-steganography/
    - https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/
tags:
    - attack.execution
    - attack.t1112
author: megan201296
date: 2019/02/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\Software\AppDataLow\Software\Microsoft\\*'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:*\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Ursnif <<EOF\n{\n  "metadata": {\n    "title": "Ursnif",\n    "description": "Detects new registry key created by Ursnif malware.",\n    "tags": [\n      "attack.execution",\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\Software\\\\\\\\AppDataLow\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\Software\\\\\\\\AppDataLow\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ursnif\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:"*\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\*")
```


### splunk
    
```
(EventID="13" TargetObject="*\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\*")
```


### logpoint
    
```
(EventID="13" TargetObject="*\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\\Software\\AppDataLow\\Software\\Microsoft\\\\.*))'
```



