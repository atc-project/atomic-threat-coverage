| Title                | Kerberos Manipulation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)</li></ul>  |
| Data Needed          | <ul><li>[DN_0078_4771_kerberos_pre_authentication_failed](../Data_Needed/DN_0078_4771_kerberos_pre_authentication_failed.md)</li><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li><li>[DN_0076_4768_kerberos_authentication_ticket_was_requested](../Data_Needed/DN_0076_4768_kerberos_authentication_ticket_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1212: Exploitation for Credential Access](../Triggers/T1212.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Faulty legacy applications</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


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





### es-qs
    
```
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Kerberos-Manipulation <<EOF\n{\n  "metadata": {\n    "title": "Kerberos Manipulation",\n    "description": "This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1212"\n    ],\n    "query": "(EventID:(\\"675\\" \\"4768\\" \\"4769\\" \\"4771\\") AND FailureCode:(\\"0x9\\" \\"0xA\\" \\"0xB\\" \\"0xF\\" \\"0x10\\" \\"0x11\\" \\"0x13\\" \\"0x14\\" \\"0x1A\\" \\"0x1F\\" \\"0x21\\" \\"0x22\\" \\"0x23\\" \\"0x24\\" \\"0x26\\" \\"0x27\\" \\"0x28\\" \\"0x29\\" \\"0x2C\\" \\"0x2D\\" \\"0x2E\\" \\"0x2F\\" \\"0x31\\" \\"0x32\\" \\"0x3E\\" \\"0x3F\\" \\"0x40\\" \\"0x41\\" \\"0x43\\" \\"0x44\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"675\\" \\"4768\\" \\"4769\\" \\"4771\\") AND FailureCode:(\\"0x9\\" \\"0xA\\" \\"0xB\\" \\"0xF\\" \\"0x10\\" \\"0x11\\" \\"0x13\\" \\"0x14\\" \\"0x1A\\" \\"0x1F\\" \\"0x21\\" \\"0x22\\" \\"0x23\\" \\"0x24\\" \\"0x26\\" \\"0x27\\" \\"0x28\\" \\"0x29\\" \\"0x2C\\" \\"0x2D\\" \\"0x2E\\" \\"0x2F\\" \\"0x31\\" \\"0x32\\" \\"0x3E\\" \\"0x3F\\" \\"0x40\\" \\"0x41\\" \\"0x43\\" \\"0x44\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Kerberos Manipulation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```


### splunk
    
```
((EventID="675" OR EventID="4768" OR EventID="4769" OR EventID="4771") (FailureCode="0x9" OR FailureCode="0xA" OR FailureCode="0xB" OR FailureCode="0xF" OR FailureCode="0x10" OR FailureCode="0x11" OR FailureCode="0x13" OR FailureCode="0x14" OR FailureCode="0x1A" OR FailureCode="0x1F" OR FailureCode="0x21" OR FailureCode="0x22" OR FailureCode="0x23" OR FailureCode="0x24" OR FailureCode="0x26" OR FailureCode="0x27" OR FailureCode="0x28" OR FailureCode="0x29" OR FailureCode="0x2C" OR FailureCode="0x2D" OR FailureCode="0x2E" OR FailureCode="0x2F" OR FailureCode="0x31" OR FailureCode="0x32" OR FailureCode="0x3E" OR FailureCode="0x3F" OR FailureCode="0x40" OR FailureCode="0x41" OR FailureCode="0x43" OR FailureCode="0x44"))
```


### logpoint
    
```
(EventID IN ["675", "4768", "4769", "4771"] FailureCode IN ["0x9", "0xA", "0xB", "0xF", "0x10", "0x11", "0x13", "0x14", "0x1A", "0x1F", "0x21", "0x22", "0x23", "0x24", "0x26", "0x27", "0x28", "0x29", "0x2C", "0x2D", "0x2E", "0x2F", "0x31", "0x32", "0x3E", "0x3F", "0x40", "0x41", "0x43", "0x44"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*675|.*4768|.*4769|.*4771))(?=.*(?:.*0x9|.*0xA|.*0xB|.*0xF|.*0x10|.*0x11|.*0x13|.*0x14|.*0x1A|.*0x1F|.*0x21|.*0x22|.*0x23|.*0x24|.*0x26|.*0x27|.*0x28|.*0x29|.*0x2C|.*0x2D|.*0x2E|.*0x2F|.*0x31|.*0x32|.*0x3E|.*0x3F|.*0x40|.*0x41|.*0x43|.*0x44)))'
```



