| Title                | Account Tampering - Suspicious Failed Logon Reasons                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1078: Valid Accounts](../Triggers/T1078.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>User using a disabled account</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Account Tampering - Suspicious Failed Logon Reasons
description: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4776
        Status:
            - '0xC0000072'
            - '0xC000006F'
            - '0xC0000070'
            - '0xC0000413'
            - '0xC000018C'
    condition: selection
falsepositives:
    - User using a disabled account
level: high

```




### es-qs
    
```
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Account-Tampering---Suspicious-Failed-Logon-Reasons <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:(\\"4625\\" \\"4776\\") AND Status:(\\"0xC0000072\\" \\"0xC000006F\\" \\"0xC0000070\\" \\"0xC0000413\\" \\"0xC000018C\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Account Tampering - Suspicious Failed Logon Reasons\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C"))
```


### splunk
    
```
((EventID="4625" OR EventID="4776") (Status="0xC0000072" OR Status="0xC000006F" OR Status="0xC0000070" OR Status="0xC0000413" OR Status="0xC000018C"))
```


### logpoint
    
```
(EventID IN ["4625", "4776"] Status IN ["0xC0000072", "0xC000006F", "0xC0000070", "0xC0000413", "0xC000018C"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4625|.*4776))(?=.*(?:.*0xC0000072|.*0xC000006F|.*0xC0000070|.*0xC0000413|.*0xC000018C)))'
```


