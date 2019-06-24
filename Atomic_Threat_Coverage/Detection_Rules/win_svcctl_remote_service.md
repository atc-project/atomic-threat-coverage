| Title                | Remote Service Activity Detected via SVCCTL named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects remote remote service activity via remote access to the svcctl named pipe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>pentesting</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html](https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Remote Service Activity Detected via SVCCTL named pipe
description: Detects remote remote service activity via remote access to the svcctl named pipe
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html
tags:
    - attack.lateral_movement
    - attack.persistence
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: svcctl
        Accesses: '*WriteData*'
    condition: selection
falsepositives: 
    - pentesting
level: medium

```





### es-qs
    
```
(EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:"svcctl" AND Accesses.keyword:*WriteData*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Remote-Service-Activity-Detected-via-SVCCTL-named-pipe <<EOF\n{\n  "metadata": {\n    "title": "Remote Service Activity Detected via SVCCTL named pipe",\n    "description": "Detects remote remote service activity via remote access to the svcctl named pipe",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.persistence"\n    ]\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"5145\\" AND ShareName:\\"\\\\\\\\*\\\\\\\\IPC$\\" AND RelativeTargetName:\\"svcctl\\" AND Accesses.keyword:*WriteData*)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Remote Service Activity Detected via SVCCTL named pipe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:"svcctl" AND Accesses:"*WriteData*")
```


### splunk
    
```
(EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*")
```


### logpoint
    
```
(EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="svcctl" Accesses="*WriteData*")
```


### grep
    
```
grep -P '^(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*svcctl)(?=.*.*WriteData.*))'
```



