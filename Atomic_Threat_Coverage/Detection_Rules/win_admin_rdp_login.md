| Title                | Admin User Remote Logon                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect remote login by Administrator user depending on internal pattern                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2016-04-005](https://car.mitre.org/wiki/CAR-2016-04-005)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2016-04-005</li><li>car.2016-04-005</li></ul> | 

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
    - car.2016-04-005
status: experimental
author: juju4
logsource:
    product: windows
    service: security
    definition: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
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





### es-qs
    
```
(EventID:"4624" AND LogonType:"10" AND AuthenticationPackageName:"Negotiate" AND AccountName.keyword:Admin\\-*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Admin-User-Remote-Logon <<EOF\n{\n  "metadata": {\n    "title": "Admin User Remote Logon",\n    "description": "Detect remote login by Administrator user depending on internal pattern",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1078",\n      "car.2016-04-005"\n    ],\n    "query": "(EventID:\\"4624\\" AND LogonType:\\"10\\" AND AuthenticationPackageName:\\"Negotiate\\" AND AccountName.keyword:Admin\\\\-*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4624\\" AND LogonType:\\"10\\" AND AuthenticationPackageName:\\"Negotiate\\" AND AccountName.keyword:Admin\\\\-*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Admin User Remote Logon\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4624" AND LogonType:"10" AND AuthenticationPackageName:"Negotiate" AND AccountName:"Admin\\-*")
```


### splunk
    
```
(EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*")
```


### logpoint
    
```
(EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*10)(?=.*Negotiate)(?=.*Admin-.*))'
```



