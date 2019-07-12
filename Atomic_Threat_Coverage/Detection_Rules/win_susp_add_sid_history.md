| Title                | Addition of SID History to Active Directory Object                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | An attacker can use the SID history attribute to gain additional privileges.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1178: SID-History Injection](https://attack.mitre.org/techniques/T1178)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1178: SID-History Injection](../Triggers/T1178.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Migration of an account into a new domain</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)</li></ul>  |
| Author               | Thomas Patzke |


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





### es-qs
    
```
EventID:("4765" "4766")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Addition-of-SID-History-to-Active-Directory-Object <<EOF\n{\n  "metadata": {\n    "title": "Addition of SID History to Active Directory Object",\n    "description": "An attacker can use the SID history attribute to gain additional privileges.",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1178"\n    ],\n    "query": "EventID:(\\"4765\\" \\"4766\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:(\\"4765\\" \\"4766\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Addition of SID History to Active Directory Object\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("4765" "4766")
```


### splunk
    
```
(EventID="4765" OR EventID="4766")
```


### logpoint
    
```
EventID IN ["4765", "4766"]
```


### grep
    
```
grep -P '^(?:.*4765|.*4766)'
```



