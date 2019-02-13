| Title                | Usage of Sysinternals Tools                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage of Sysinternals Tools due to accepteula key beeing added to Registry                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Legitimate use of SysInternals tools</li><li>Programs that use the same Registry Key</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/Moti_B/status/1008587936735035392](https://twitter.com/Moti_B/status/1008587936735035392)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Usage of Sysinternals Tools 
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key beeing added to Registry 
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
author: Markus Neis
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: '*\EulaAccepted'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low


```





### Kibana query

```
(EventID:"13" AND TargetObject.keyword:*\\\\EulaAccepted)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Usage-of-Sysinternals-Tools <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\EulaAccepted)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Usage of Sysinternals Tools\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"13" AND TargetObject:"*\\\\EulaAccepted")
```

