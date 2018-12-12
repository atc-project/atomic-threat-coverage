| Title        | Admin User Remote Logon |
|:-------------------|:------------------|
| Description        | Detect remote login by Administrator user depending on internal pattern |
| Tags               |   |
| ATT&amp;CK Tactic | ('Lateral Movement', 'TA0008')  |
| ATT&amp;CK Technique | T1078  |
| Dataneeded         | DN_0004_windows_account_logon_4624 |
| Triggering         | T1078: No atomics trigger for this technique |
| Severity Level     | low       |
| False Positives    | Legitimate administrative activity |
| Development Status | experimental      |
| References         | https://car.mitre.org/wiki/CAR-2016-04-005 |
| Author             | juju4      |


## Detection Rules

### Sigma rule

```
title: Admin User Remote Logon
description: Detect remote login by Administrator user depending on internal pattern
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
tags:
    - attack.lateral_movement
    - attack.t1078
status: experimental
author: juju4
logsource:
    product: windows
    service: security
    description: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
detection:
    selection:
        EventID: 4624
        LogonType: 10
        AuthenticationPackageName: Negotiate
        AccountName: 'Admin-*'
    condition: selection
falsepositives: 
    - Legitimate administrative activity
level: low

```





### Kibana query

```
(EventID:"4624" AND LogonType:"10" AND AuthenticationPackageName:"Negotiate" AND AccountName:"Admin\\-*")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Admin-User-Remote-Logon <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4624\\" AND LogonType:\\"10\\" AND AuthenticationPackageName:\\"Negotiate\\" AND AccountName:\\"Admin\\\\-*\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Admin User Remote Logon\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4624" AND LogonType:"10" AND AuthenticationPackageName:"Negotiate" AND AccountName:"Admin\\-*")
```

