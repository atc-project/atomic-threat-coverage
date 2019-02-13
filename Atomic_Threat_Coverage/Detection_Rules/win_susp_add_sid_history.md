| Title                | Addition of SID History to Active Directory Object                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An attacker can use the SID history attribute to gain additional privileges.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1178: SID-History Injection](https://attack.mitre.org/techniques/T1178)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1178: SID-History Injection](../Triggers/T1178.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Migration of an account into a new domain</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
| Other Tags           | <ul><li>attack.privilege_escalation</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Addition of SID History to Active Directory Object
status: stable
description: An attacker can use the SID history attribute to gain additional privileges.
references:
    - https://adsecurity.org/?p=1772
author: Thomas Patzke
tags:
    - attack.privilege_escalation
    - attack.t1178
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4765
            - 4766
    condition: selection
falsepositives:
    - Migration of an account into a new domain
level: medium

```





### Kibana query

```
EventID:("4765" "4766")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Addition-of-SID-History-to-Active-Directory-Object <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "EventID:(\\"4765\\" \\"4766\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Addition of SID History to Active Directory Object\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
EventID:("4765" "4766")
```

