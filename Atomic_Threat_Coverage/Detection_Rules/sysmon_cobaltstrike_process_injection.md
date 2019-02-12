| Title                | CobaltStrike Process Injection                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1055](https://attack.mitre.org/tactics/T1055)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1055](../Triggers/T1055.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f](https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f)</li></ul>                                                          |
| Author               | Olaf Hartong, Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.process_injection</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CobaltStrike Process Injection 
description: Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons 
references:
    - https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
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
tags:
    - attack.process_injection
    - attack.t1055
falsepositives:
    - unknown
level: high


```





### Kibana query

```
(EventID:"8" AND TargetProcessAddress.keyword:*0B80)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/CobaltStrike-Process-Injection <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"8\\" AND TargetProcessAddress.keyword:*0B80)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'CobaltStrike Process Injection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"8" AND TargetProcessAddress:"*0B80")
```

