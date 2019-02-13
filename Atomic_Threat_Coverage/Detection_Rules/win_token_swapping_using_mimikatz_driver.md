| Title                | Token swapping using Mimikatz driver                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detection of child processes spawned under SYSTEM by process with High integrity level                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1134](https://attack.mitre.org/tactics/T1134)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1134](../Triggering/T1134.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Todo</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul>                                                          |
| Author               | Teymur Kheirkhabarov                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Token swapping using Mimikatz driver
description: Detection of child processes spawned under SYSTEM by process with High integrity level
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1134
status: experimental
author: Teymur Kheirkhabarov
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentIntegrityLevel: High
        IntegrityLevel: System
        User: "NT AUTHORITY\\SYSTEM"
    condition: selection
falsepositives: 
    - Todo
level: critical
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info
    - EN_0002_enrich_sysmon_event_id_1_with_parent_info

```





### Kibana query

```
(EventID:"1" AND ParentIntegrityLevel:"High" AND IntegrityLevel:"System" AND User:"NT AUTHORITY\\\\SYSTEM")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Token-swapping-using-Mimikatz-driver <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ParentIntegrityLevel:\\"High\\" AND IntegrityLevel:\\"System\\" AND User:\\"NT AUTHORITY\\\\\\\\SYSTEM\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Token swapping using Mimikatz driver\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND ParentIntegrityLevel:"High" AND IntegrityLevel:"System" AND User:"NT AUTHORITY\\\\SYSTEM")
```

