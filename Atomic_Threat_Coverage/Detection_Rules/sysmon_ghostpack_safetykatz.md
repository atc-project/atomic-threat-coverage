| Title                | Detection of SafetyKatz                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects possible SafetyKatz Behaviour                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


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
date: 2018/24/07
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





### Kibana query

```
(EventID:"11" AND TargetFilename.keyword:*\\\\Temp\\\\debug.bin)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Detection-of-SafetyKatz <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\Temp\\\\\\\\debug.bin)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Detection of SafetyKatz\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"11" AND TargetFilename:"*\\\\Temp\\\\debug.bin")
```

