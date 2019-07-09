| Title                | Detection of SafetyKatz                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects possible SafetyKatz Behaviour                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Detection of SafetyKatz
status: experimental
description: Detects possible SafetyKatz Behaviour
references:
    - https://github.com/GhostPack/SafetyKatz
tags:
    - attack.credential_access
    - attack.t1003
author: Markus Neis
date: 2018/07/24
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename: '*\Temp\debug.bin'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"11" AND TargetFilename.keyword:*\\\\Temp\\\\debug.bin)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Detection-of-SafetyKatz <<EOF\n{\n  "metadata": {\n    "title": "Detection of SafetyKatz",\n    "description": "Detects possible SafetyKatz Behaviour",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\Temp\\\\\\\\debug.bin)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\Temp\\\\\\\\debug.bin)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Detection of SafetyKatz\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"11" AND TargetFilename:"*\\\\Temp\\\\debug.bin")
```


### splunk
    
```
(EventID="11" TargetFilename="*\\\\Temp\\\\debug.bin")
```


### logpoint
    
```
(EventID="11" TargetFilename="*\\\\Temp\\\\debug.bin")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*\\Temp\\debug\\.bin))'
```



