| Title                | CobaltStrike Process Injection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f](https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f)</li></ul>  |
| Author               | Olaf Hartong, Florian Roth |


## Detection Rules

### Sigma rule

```
title: CobaltStrike Process Injection 
description: Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons 
references:
    - https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
tags:
    - attack.defense_evasion
    - attack.t1055
status: experimental
author: Olaf Hartong, Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetProcessAddress: '*0B80'
    condition: selection
falsepositives:
    - unknown
level: high


```





### es-qs
    
```
(EventID:"8" AND TargetProcessAddress.keyword:*0B80)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/CobaltStrike-Process-Injection <<EOF\n{\n  "metadata": {\n    "title": "CobaltStrike Process Injection",\n    "description": "Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1055"\n    ],\n    "query": "(EventID:\\"8\\" AND TargetProcessAddress.keyword:*0B80)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"8\\" AND TargetProcessAddress.keyword:*0B80)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'CobaltStrike Process Injection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"8" AND TargetProcessAddress:"*0B80")
```


### splunk
    
```
(EventID="8" TargetProcessAddress="*0B80")
```


### logpoint
    
```
(EventID="8" TargetProcessAddress="*0B80")
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*.*0B80))'
```



