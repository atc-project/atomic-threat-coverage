| Title                | Kerberos Manipulation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212](https://attack.mitre.org/tactics/T1212)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1212](../Triggers/T1212.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Faulty legacy applications</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Kerberos Manipulation
description: This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages
author: Florian Roth
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
          - 675
          - 4768
          - 4769
          - 4771
        FailureCode:
          - '0x9'
          - '0xA'
          - '0xB'
          - '0xF'
          - '0x10'
          - '0x11'
          - '0x13'
          - '0x14'
          - '0x1A'
          - '0x1F'
          - '0x21'
          - '0x22'
          - '0x23'
          - '0x24'
          - '0x26'
          - '0x27'
          - '0x28'
          - '0x29'
          - '0x2C'
          - '0x2D'
          - '0x2E'
          - '0x2F'
          - '0x31'
          - '0x32'
          - '0x3E'
          - '0x3F'
          - '0x40'
          - '0x41'
          - '0x43'
          - '0x44'
    condition: selection
falsepositives:
    - Faulty legacy applications
level: high

```





### Kibana query

```
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Kerberos-Manipulation <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:(\\"675\\" \\"4768\\" \\"4769\\" \\"4771\\") AND FailureCode:(\\"0x9\\" \\"0xA\\" \\"0xB\\" \\"0xF\\" \\"0x10\\" \\"0x11\\" \\"0x13\\" \\"0x14\\" \\"0x1A\\" \\"0x1F\\" \\"0x21\\" \\"0x22\\" \\"0x23\\" \\"0x24\\" \\"0x26\\" \\"0x27\\" \\"0x28\\" \\"0x29\\" \\"0x2C\\" \\"0x2D\\" \\"0x2E\\" \\"0x2F\\" \\"0x31\\" \\"0x32\\" \\"0x3E\\" \\"0x3F\\" \\"0x40\\" \\"0x41\\" \\"0x43\\" \\"0x44\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Kerberos Manipulation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```

