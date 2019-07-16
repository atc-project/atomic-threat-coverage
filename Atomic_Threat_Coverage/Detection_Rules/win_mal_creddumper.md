| Title                | Malicious Service Install                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects well-known keywords of malicious services in the Windows System Eventlog                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li><li>[DN_0083_16_access_history_in_hive_was_cleared](../Data_Needed/DN_0083_16_access_history_in_hive_was_cleared.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: Malicious Service Install
description: This method detects well-known keywords of malicious services in the Windows System Eventlog 
author: Florian Roth
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: system
detection:
    selection1:
        EventID: 
          - 7045
    keywords:
      - 'WCE SERVICE'
      - 'WCESERVICE'
      - 'DumpSvc'
    quarkspwdump:
        EventID: 16
        HiveName: '*\AppData\Local\Temp\SAM*.dmp'
    condition: ( selection1 and keywords ) or ( selection2 and keywords ) or quarkspwdump
falsepositives:
    - Unlikely
level: high
---
logsource:
    product: windows
    service: security
detection:
    selection2:
        EventID: 4697

```





### es-qs
    
```
(((EventID:("7045") AND ("WCE\\ SERVICE" OR "WCESERVICE" OR "DumpSvc")) OR (EventID:"4697" AND ("WCE\\ SERVICE" OR "WCESERVICE" OR "DumpSvc"))) OR (EventID:"16" AND HiveName.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM*.dmp))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Malicious-Service-Install <<EOF\n{\n  "metadata": {\n    "title": "Malicious Service Install",\n    "description": "This method detects well-known keywords of malicious services in the Windows System Eventlog",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.s0005"\n    ],\n    "query": "(((EventID:(\\"7045\\") AND (\\"WCE\\\\ SERVICE\\" OR \\"WCESERVICE\\" OR \\"DumpSvc\\")) OR (EventID:\\"4697\\" AND (\\"WCE\\\\ SERVICE\\" OR \\"WCESERVICE\\" OR \\"DumpSvc\\"))) OR (EventID:\\"16\\" AND HiveName.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM*.dmp))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((EventID:(\\"7045\\") AND (\\"WCE\\\\ SERVICE\\" OR \\"WCESERVICE\\" OR \\"DumpSvc\\")) OR (EventID:\\"4697\\" AND (\\"WCE\\\\ SERVICE\\" OR \\"WCESERVICE\\" OR \\"DumpSvc\\"))) OR (EventID:\\"16\\" AND HiveName.keyword:*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Temp\\\\\\\\SAM*.dmp))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Service Install\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((EventID:("7045") AND ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc")) OR (EventID:"4697" AND ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc"))) OR (EventID:"16" AND HiveName:"*\\\\AppData\\\\Local\\\\Temp\\\\SAM*.dmp"))
```


### splunk
    
```
((((EventID="7045") ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc")) OR (EventID="4697" ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc"))) OR (EventID="16" HiveName="*\\\\AppData\\\\Local\\\\Temp\\\\SAM*.dmp"))
```


### logpoint
    
```
(((EventID IN ["7045"] ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc")) OR (EventID="4697" ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc"))) OR (EventID="16" HiveName="*\\\\AppData\\\\Local\\\\Temp\\\\SAM*.dmp"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*(?:.*7045))(?=.*(?:.*(?:.*WCE SERVICE|.*WCESERVICE|.*DumpSvc))))|.*(?:.*(?=.*4697)(?=.*(?:.*(?:.*WCE SERVICE|.*WCESERVICE|.*DumpSvc))))))|.*(?:.*(?=.*16)(?=.*.*\\AppData\\Local\\Temp\\SAM.*\\.dmp))))'
```



